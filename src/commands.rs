use std::io::Write;

use anyhow::{bail, Result};
use serde::Serialize;

use crate::backend::ProcessBackend;
use crate::cli::{Cli, Command, StartupAction, Target};
use crate::decode::{self, fmt_ptr, DataType, TypeSpec};
use crate::format::{self, addr, human_size};
use crate::infer::{self, InferCtx};
use crate::model::{ser_hex, MemKind, MemState, Region, TypeDesc};
use crate::search;
use crate::session::{name_matches, resolve_target, Session, SessionOptions};

pub struct Ctx<'a> {
    pub cli: &'a Cli,
    pub backend: &'a dyn ProcessBackend,
    pub out: &'a mut dyn Write,
}

impl Ctx<'_> {
    fn open(&self, t: &Target) -> Result<Session> {
        let info = resolve_target(self.backend, t.pid, t.name.as_deref())?;
        Session::open(
            self.backend,
            &info,
            SessionOptions {
                debug_privilege: self.cli.debug_priv,
                suspend: self.cli.suspend,
                symbol_path: self.cli.symbols.clone(),
                no_symbols: self.cli.no_symbols,
            },
        )
    }
}

fn header(out: &mut dyn Write, s: &Session) -> Result<()> {
    let i = s.info();
    writeln!(
        out,
        "# {} (pid {}, {}-bit){}",
        i.name,
        i.pid,
        s.ptr_size() * 8,
        i.path.as_deref().map(|p| format!(" {p}")).unwrap_or_default()
    )?;
    Ok(())
}

fn warn(s: &Session) {
    for w in &s.warnings {
        eprintln!("warning: {w}");
    }
}

pub fn run(ctx: &mut Ctx) -> Result<()> {
    let json = ctx.cli.json;
    match &ctx.cli.command {
        Command::Dump { target, file } => {
            let target = resolve_target(ctx.backend, target.pid, target.name.as_deref())?;
            let process = ctx.backend.open(target.pid, &crate::backend::OpenOptions {
                debug_privilege: ctx.cli.debug_priv,
                ..Default::default()
            })?;
            let report = process.dump(file)?;
            if json { format::json(ctx.out, &report)?; }
            else {
                writeln!(ctx.out, "Dump: {} ({} bytes)", report.path, report.bytes)?;
                writeln!(ctx.out, "Capture interval: {}..{} ms since Unix epoch", report.capture_started_unix_ms, report.capture_completed_unix_ms)?;
                for warning in report.warnings { writeln!(ctx.out, "Warning: {warning}")?; }
            }
        }
        Command::Startup { action } => {
            let status = match action {
                StartupAction::Status => crate::startup::status()?,
                StartupAction::Enable { executable } => crate::startup::enable(executable)?,
                StartupAction::Disable => crate::startup::disable()?,
            };
            if json { format::json(ctx.out, &status)?; }
            else {
                writeln!(ctx.out, "Sign-in startup: {}", if status.enabled { "enabled" } else { "disabled" })?;
                if let Some(command) = status.command { writeln!(ctx.out, "Executable: {command}")?; }
            }
        }
        Command::Ps { filter } => {
            let mut procs = ctx.backend.list_processes()?;
            if let Some(f) = filter {
                procs.retain(|p| name_matches(f, &p.name));
            }
            procs.sort_by_key(|p| p.pid);
            if json {
                return Ok(format::json(ctx.out, &procs)?);
            }
            let rows: Vec<Vec<String>> = procs
                .iter()
                .map(|p| vec![p.pid.to_string(), p.ppid.to_string(), p.threads.to_string(), p.name.clone()])
                .collect();
            format::table(ctx.out, &["PID", "PPID", "Threads", "Name"], &rows)?;
        }

        Command::Regions { target, all, committed, readable, writable, exec, kind, label } => {
            let s = ctx.open(target)?;
            let ps = s.ptr_size();
            let label = label.as_ref().map(|l| l.to_lowercase());
            let regions: Vec<&Region> = s
                .map
                .regions()
                .iter()
                .filter(|r| *all || r.state != MemState::Free)
                .filter(|r| !*committed || r.state == MemState::Commit)
                .filter(|r| !*readable || r.is_readable())
                .filter(|r| !*writable || (r.state == MemState::Commit && r.protect.writable()))
                .filter(|r| !*exec || (r.state == MemState::Commit && r.protect.executable()))
                .filter(|r| kind.as_deref().is_none_or(|k| r.kind.to_string() == k))
                .filter(|r| {
                    label.as_deref().is_none_or(|l| r.label.as_deref().is_some_and(|x| x.to_lowercase().contains(l)))
                })
                .collect();
            if json {
                format::json(ctx.out, &regions)?;
            } else {
                header(ctx.out, &s)?;
                let rows: Vec<Vec<String>> = regions
                    .iter()
                    .map(|r| {
                        vec![
                            addr(r.base, ps),
                            addr(r.end(), ps),
                            human_size(r.size),
                            r.state.to_string(),
                            r.protect.to_string(),
                            r.kind.to_string(),
                            r.label.clone().unwrap_or_default(),
                        ]
                    })
                    .collect();
                format::table(ctx.out, &["Base", "End", "Size", "State", "Prot", "Type", "Label"], &rows)?;
                let committed: u64 = regions.iter().filter(|r| r.state == MemState::Commit).map(|r| r.size).sum();
                writeln!(ctx.out, "\n{} regions, {} committed", regions.len(), human_size(committed))?;
            }
            warn(&s);
        }

        Command::Modules { target, sections } => {
            let s = ctx.open(target)?;
            let ps = s.ptr_size();
            if json {
                format::json(ctx.out, &s.modules)?;
            } else {
                header(ctx.out, &s)?;
                let mut rows = Vec::new();
                for m in &s.modules {
                    rows.push(vec![addr(m.base, ps), human_size(m.size), m.name.clone(), m.path.clone()]);
                    if *sections {
                        for sec in &m.sections {
                            rows.push(vec![
                                format!("  {}", addr(sec.base, ps)),
                                human_size(sec.size),
                                format!("  {}", sec.name),
                                sec.flags.clone(),
                            ]);
                        }
                    }
                }
                format::table(ctx.out, &["Base", "Size", "Name", "Path"], &rows)?;
            }
            warn(&s);
        }

        Command::Threads { target } => {
            let s = ctx.open(target)?;
            let ps = s.ptr_size();
            if json {
                format::json(ctx.out, &s.threads)?;
            } else {
                header(ctx.out, &s)?;
                let mut rows = Vec::new();
                for t in &s.threads {
                    if t.stacks.is_empty() {
                        rows.push(vec![t.tid.to_string(), addr(t.teb, 8), String::new(), String::new(), String::new()]);
                    }
                    for st in &t.stacks {
                        rows.push(vec![
                            t.tid.to_string(),
                            addr(t.teb, 8),
                            addr(st.limit, ps),
                            addr(st.base, ps),
                            if st.wow64 { "wow64".into() } else { human_size(st.base - st.limit) },
                        ]);
                    }
                }
                format::table(ctx.out, &["TID", "TEB", "Stack limit", "Stack base", "Committed"], &rows)?;
            }
            warn(&s);
        }

        Command::Read { target, addr: expr, len, as_type } => {
            let mut s = ctx.open(target)?;
            let a = s.resolve_addr(expr)?;
            let ps = s.ptr_size();
            let spec: TypeSpec = match as_type {
                Some(t) => t.parse()?,
                None => TypeSpec { ty: DataType::Hex, count: None },
            };
            let len = match spec.count {
                Some(c) if !spec.ty.is_string() && spec.ty != DataType::Hex => c * spec.ty.size(ps),
                _ => *len,
            };
            let r = s.read(a, len);
            if r.valid_count() == 0 {
                bail!("0x{a:x} is not readable ({})", describe_region(&s, a));
            }
            if spec.ty == DataType::Hex {
                if json {
                    #[derive(Serialize)]
                    struct Dump {
                        #[serde(serialize_with = "ser_hex")]
                        addr: u64,
                        len: usize,
                        hex: String,
                    }
                    let hex = r
                        .bytes
                        .iter()
                        .zip(&r.valid)
                        .map(|(b, v)| if *v { format!("{b:02x}") } else { "??".into() })
                        .collect::<Vec<_>>()
                        .join("");
                    format::json(ctx.out, &Dump { addr: a, len, hex })?;
                } else {
                    format::hexdump(ctx.out, &r, ps)?;
                }
            } else {
                let bytes = r.valid_prefix();
                let vals = decode::decode_spec(spec, bytes, ps);
                if json {
                    #[derive(Serialize)]
                    struct Val {
                        #[serde(serialize_with = "ser_hex")]
                        addr: u64,
                        #[serde(rename = "type")]
                        ty: DataType,
                        value: String,
                    }
                    let v: Vec<Val> =
                        vals.into_iter().map(|(o, value)| Val { addr: a + o as u64, ty: spec.ty, value }).collect();
                    format::json(ctx.out, &v)?;
                } else {
                    for (o, v) in vals {
                        let extra = if spec.ty == DataType::Ptr {
                            let p = decode::read_uint(&bytes[o..], ps);
                            if s.map.is_committed(p) { format!("  -> {}", s.describe(p)) } else { String::new() }
                        } else {
                            String::new()
                        };
                        writeln!(ctx.out, "{}  {:<8} {v}{extra}", format::addr(a + o as u64, ps), spec.ty.name())?;
                    }
                }
            }
            warn(&s);
        }

        Command::Inspect { target, addr: expr, len } => {
            let mut s = ctx.open(target)?;
            let a = s.resolve_addr(expr)?;
            let ps = s.ptr_size();
            let r = s.read(a, *len);
            if r.valid_count() == 0 {
                bail!("0x{a:x} is not readable ({})", describe_region(&s, a));
            }
            let use_symbols = !ctx.cli.no_symbols;
            let anns = infer::annotate(&mut s, &r, use_symbols);
            if json {
                format::json(ctx.out, &anns)?;
            } else {
                header(ctx.out, &s)?;
                writeln!(ctx.out, "# {} ({})\n", fmt_ptr(a, ps), describe_region(&s, a))?;
                format::annotations(ctx.out, &r, &anns, ps)?;
            }
            warn(&s);
        }

        Command::Symbol { target, query } => {
            let mut s = ctx.open(target)?;
            let ps = s.ptr_size();
            #[derive(Serialize)]
            struct Res {
                #[serde(serialize_with = "ser_hex")]
                address: u64,
                symbol: Option<String>,
                region: String,
                #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
                ty: Option<String>,
            }
            let a = s.resolve_addr(query)?;
            let hit = InferCtx::symbol(&mut s, a);
            let res = Res {
                address: a,
                symbol: s.symbolize(a),
                region: describe_region(&s, a),
                ty: hit.and_then(|h| h.ty).map(|t| t.name()),
            };
            if json {
                format::json(ctx.out, &res)?;
            } else {
                writeln!(ctx.out, "address : {}", fmt_ptr(res.address, ps))?;
                writeln!(ctx.out, "symbol  : {}", res.symbol.as_deref().unwrap_or("-"))?;
                if let Some(t) = &res.ty {
                    writeln!(ctx.out, "type    : {t}")?;
                }
                writeln!(ctx.out, "region  : {}", res.region)?;
            }
            warn(&s);
        }

        Command::Globals { target, module, filter } => {
            let mut s = ctx.open(target)?;
            let ps = s.ptr_size();
            let Some(m) = s.find_module(module).cloned() else { bail!("module '{module}' not loaded") };
            let Some(syms) = s.symbols() else { bail!("symbols unavailable") };
            let hits = syms.globals(m.base, filter);
            if hits.is_empty() {
                eprintln!("no data symbols found - is the PDB for {} available? (see --symbols)", m.name);
            }
            if json {
                format::json(ctx.out, &hits)?;
            } else {
                header(ctx.out, &s)?;
                let mut rows = Vec::new();
                for h in &hits {
                    let preview = match &h.ty {
                        Some(TypeDesc::Struct { .. }) => "{...}".into(),
                        Some(t) => {
                            let r = s.read(h.address, (t.size() as usize).clamp(1, 256));
                            infer::symbol_annotations(&mut s, h, &r)
                                .first()
                                .map(|a| a.value.clone())
                                .unwrap_or_default()
                        }
                        None => String::new(),
                    };
                    rows.push(vec![
                        addr(h.address, ps),
                        h.size.to_string(),
                        h.ty.as_ref().map(TypeDesc::name).unwrap_or_default(),
                        h.name.clone(),
                        preview,
                    ]);
                }
                format::table(ctx.out, &["Address", "Size", "Type", "Name", "Value"], &rows)?;
            }
            warn(&s);
        }

        Command::Search { target, pattern, aligned, max } => {
            let mut s = ctx.open(target)?;
            let ps = s.ptr_size();
            let (pat, natural) = pattern.bytes()?;
            let align = if *aligned { natural } else { 1 };
            let hits = search::search(&*s.proc, &s.map, &pat, align, 0, *max);
            #[derive(Serialize)]
            struct Hit {
                #[serde(serialize_with = "ser_hex")]
                address: u64,
                location: String,
            }
            let hits: Vec<Hit> = hits.into_iter().map(|a| Hit { address: a, location: s.describe(a) }).collect();
            if json {
                format::json(ctx.out, &hits)?;
            } else {
                header(ctx.out, &s)?;
                let rows: Vec<Vec<String>> = hits.iter().map(|h| vec![addr(h.address, ps), h.location.clone()]).collect();
                format::table(ctx.out, &["Address", "Location"], &rows)?;
                writeln!(ctx.out, "\n{} hit(s){}", hits.len(), if hits.len() >= *max { " (limit reached, see --max)" } else { "" })?;
            }
            warn(&s);
        }

        #[cfg(feature = "tui")]
        Command::Tui { target, addr: start } => {
            let mut s = ctx.open(target)?;
            let start = match start {
                Some(e) => Some(s.resolve_addr(e)?),
                None => None,
            };
            crate::tui::run(&mut s, start)?;
            warn(&s);
        }
    }
    Ok(())
}

pub fn describe_region(s: &Session, a: u64) -> String {
    match s.map.find(a) {
        Some(r) => {
            let what = match r.kind {
                MemKind::None => r.state.to_string(),
                k => format!("{k} {}", r.state),
            };
            match &r.label {
                Some(l) => format!("{l}; {what} {}", r.protect),
                None => format!("{what} {}", r.protect),
            }
        }
        None => "unmapped".into(),
    }
}
