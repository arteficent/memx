//! An opened target with its region map, modules, threads, caches and lazy symbols.

use anyhow::{anyhow, bail, Context, Result};

use crate::backend::{OpenOptions, Process, ProcessBackend, SymbolProvider};
use crate::infer::InferCtx;
use crate::model::{MemKind, Module, ProcessExtras, ProcessInfo, Region, SymbolHit, ThreadInfo};
use crate::reader::{PageCache, ReadResult};
use crate::regionmap::RegionMap;
use crate::{labels, pe};

#[derive(Debug, Clone, Default)]
pub struct SessionOptions {
    pub debug_privilege: bool,
    pub suspend: bool,
    pub symbol_path: Option<String>,
    pub no_symbols: bool,
}

pub struct Session {
    // Field order matters: symbols must drop before the process handle.
    symbols: Option<Box<dyn SymbolProvider>>,
    symbols_tried: bool,
    exports: Option<Vec<(u64, String)>>,
    cache: PageCache,
    pub map: RegionMap,
    pub modules: Vec<Module>,
    pub threads: Vec<ThreadInfo>,
    pub extras: ProcessExtras,
    pub warnings: Vec<String>,
    opts: SessionOptions,
    suspended: bool,
    pub proc: Box<dyn Process>,
}

/// Matches `name` against a glob with `*` and `?`, case-insensitively.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

pub fn name_matches(pattern: &str, exe: &str) -> bool {
    let stem = exe.strip_suffix(".exe").or_else(|| exe.strip_suffix(".EXE")).unwrap_or(exe);
    glob_match(pattern, exe) || glob_match(pattern, stem)
}

pub fn resolve_target(backend: &dyn ProcessBackend, pid: Option<u32>, name: Option<&str>) -> Result<ProcessInfo> {
    let procs = backend.list_processes()?;
    if let Some(pid) = pid {
        return procs
            .into_iter()
            .find(|p| p.pid == pid)
            .ok_or_else(|| anyhow!("no running process with pid {pid}"));
    }
    let pattern = name.ok_or_else(|| anyhow!("specify --pid or --name"))?;
    let mut hits: Vec<ProcessInfo> = procs.into_iter().filter(|p| name_matches(pattern, &p.name)).collect();
    match hits.len() {
        0 => bail!("no running process matches '{pattern}'"),
        1 => Ok(hits.remove(0)),
        _ => {
            let list: Vec<String> = hits.iter().map(|p| format!("  {:>6}  {}", p.pid, p.name)).collect();
            bail!("'{pattern}' matches {} processes; pick one with --pid:\n{}", hits.len(), list.join("\n"))
        }
    }
}

pub fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim().replace(['_', '`'], "");
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse().ok();
    }
    u64::from_str_radix(&s, 16).ok()
}

impl Session {
    pub fn open(backend: &dyn ProcessBackend, target: &ProcessInfo, opts: SessionOptions) -> Result<Self> {
        let proc = backend.open(
            target.pid,
            &OpenOptions { debug_privilege: opts.debug_privilege, suspend_access: opts.suspend },
        )?;
        let mut s = Self {
            symbols: None,
            symbols_tried: false,
            exports: None,
            cache: PageCache::new(512),
            map: RegionMap::default(),
            modules: Vec::new(),
            threads: Vec::new(),
            extras: ProcessExtras::default(),
            warnings: Vec::new(),
            suspended: false,
            opts,
            proc,
        };
        if s.opts.suspend {
            s.proc.suspend().context("suspending target")?;
            s.suspended = true;
        }
        s.refresh()?;
        Ok(s)
    }

    pub fn info(&self) -> &ProcessInfo {
        self.proc.info()
    }

    /// Re-reads regions, modules, threads and labels; drops cached pages.
    pub fn refresh(&mut self) -> Result<()> {
        self.cache.clear();
        self.symbols = None;
        self.symbols_tried = false;
        self.warnings.clear();
        let mut regions = self.proc.regions().context("enumerating memory regions")?;
        regions.sort_by_key(|r| r.base);
        let proc = &*self.proc;
        let mapped = |a: u64| proc.mapped_file_name(a);

        let mut modules = match proc.modules() {
            Ok(m) => m,
            Err(e) => {
                self.warnings.push(format!("modules: {e:#}; derived from image regions instead"));
                labels::modules_from_regions(&regions, &mapped)
            }
        };
        for m in &mut modules {
            let mut hdr = vec![0u8; 0x1000];
            let n = proc.read_raw(m.base, &mut hdr);
            if let Some(h) = pe::parse_headers(m.base, &hdr[..n]) {
                m.sections = h.sections;
                m.export_dir = h.export_dir;
            }
        }
        let threads = proc.threads().unwrap_or_else(|e| {
            self.warnings.push(format!("threads: {e:#}"));
            Vec::new()
        });
        let extras = proc.extras().unwrap_or_else(|e| {
            self.warnings.push(format!("PEB/heaps: {e:#}"));
            ProcessExtras::default()
        });
        labels::apply(&mut regions, &modules, &threads, &extras, &mapped);
        self.map = RegionMap::new(regions);
        self.modules = modules;
        self.threads = threads;
        self.extras = extras;
        self.exports = None;
        Ok(())
    }

    pub fn ptr_size(&self) -> usize {
        self.proc.pointer_size()
    }

    pub fn read(&mut self, addr: u64, len: usize) -> ReadResult {
        self.cache.read(&*self.proc, &self.map, addr, len)
    }

    pub fn clear_reads(&mut self) {
        self.cache.clear();
    }

    pub fn module_at(&self, addr: u64) -> Option<&Module> {
        let i = self.modules.partition_point(|m| m.base <= addr);
        (i > 0 && self.modules[i - 1].contains(addr)).then(|| &self.modules[i - 1])
    }

    pub fn find_module(&self, name: &str) -> Option<&Module> {
        let n = name.to_ascii_lowercase();
        self.modules
            .iter()
            .find(|m| m.name.to_ascii_lowercase() == n || m.stem() == n)
    }

    pub fn symbols(&mut self) -> Option<&dyn SymbolProvider> {
        if !self.symbols_tried && !self.opts.no_symbols {
            self.symbols_tried = true;
            let path = self.opts.symbol_path.clone().or_else(|| std::env::var("_NT_SYMBOL_PATH").ok());
            match self.proc.load_symbols(path.as_deref(), &self.modules) {
                Ok(s) => self.symbols = Some(s),
                Err(e) => self.warnings.push(format!("symbols: {e:#}")),
            }
        }
        self.symbols.as_deref()
    }

    fn exports(&mut self) -> &[(u64, String)] {
        if self.exports.is_none() {
            let mut all = Vec::new();
            for m in &self.modules {
                let Some(dir) = m.export_dir else { continue };
                let proc = &*self.proc;
                let mut read = |a: u64, n: usize| {
                    let mut b = vec![0u8; n];
                    let got = proc.read_raw(a, &mut b);
                    (got == n).then_some(b)
                };
                for (a, name) in pe::parse_exports(m.base, dir, &mut read) {
                    all.push((a, format!("{}!{name}", m.name)));
                }
            }
            all.sort_by_key(|e| e.0);
            self.exports = Some(all);
        }
        self.exports.as_deref().unwrap_or_default()
    }

    /// `module!symbol+0xNN` for code/data addresses inside modules.
    pub fn symbolize(&mut self, addr: u64) -> Option<String> {
        let module = self.module_at(addr)?.clone();
        if let Some(hit) = self.symbols().and_then(|s| s.lookup_addr(addr)) {
            if module.contains(hit.address) && !hit.name.ends_with('!') {
                return Some(if hit.displacement == 0 {
                    hit.name
                } else {
                    format!("{}+0x{:x}", hit.name, hit.displacement)
                });
            }
        }
        let exec = module.section_at(addr).is_some_and(|s| s.flags.contains('X'));
        if exec {
            let ex = self.exports();
            let i = ex.partition_point(|e| e.0 <= addr);
            if i > 0 && module.contains(ex[i - 1].0) {
                let (a, n) = &ex[i - 1];
                return Some(if *a == addr { n.clone() } else { format!("{n}+0x{:x}", addr - a) });
            }
        }
        None
    }

    /// Resolves `0x…`, `123`, `module`, `module+0x10`, `module!symbol[+off]`.
    pub fn resolve_addr(&mut self, expr: &str) -> Result<u64> {
        let expr = expr.trim();
        if let Some((lhs, rhs)) = expr.rsplit_once('+') {
            let off = parse_number(rhs).ok_or_else(|| anyhow!("bad offset '{rhs}'"))?;
            return Ok(self.resolve_addr(lhs)?.wrapping_add(off));
        }
        if let Some(v) = parse_number(expr) {
            if expr.starts_with("0x") || expr.chars().all(|c| c.is_ascii_digit()) || self.find_module(expr).is_none() {
                return Ok(v);
            }
        }
        if expr.contains('!') {
            if let Some(hit) = self.symbols().and_then(|s| s.lookup_name(expr)) {
                return Ok(hit.address);
            }
            let (m, sym) = expr.split_once('!').unwrap();
            let mname = self.find_module(m).map(|m| m.name.clone());
            if let Some(mname) = mname {
                let want = format!("{mname}!{sym}");
                if let Some((a, _)) = self.exports().iter().find(|(_, n)| n.eq_ignore_ascii_case(&want)) {
                    return Ok(*a);
                }
            }
            bail!("symbol '{expr}' not found (are PDBs available? see --symbols)");
        }
        if let Some(m) = self.find_module(expr) {
            return Ok(m.base);
        }
        bail!("cannot resolve address '{expr}'")
    }

    pub fn region_label(&self, r: &Region) -> String {
        r.label.clone().unwrap_or_else(|| r.kind.to_string())
    }
}

impl InferCtx for Session {
    fn ptr_size(&self) -> usize {
        self.proc.pointer_size()
    }

    fn region(&self, addr: u64) -> Option<&Region> {
        self.map.find(addr)
    }

    fn module_base(&self, addr: u64) -> Option<u64> {
        self.module_at(addr).map(|m| m.base)
    }

    fn peek(&mut self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let r = self.read(addr, len);
        let p = r.valid_prefix();
        (!p.is_empty()).then(|| p.to_vec())
    }

    fn symbol(&mut self, addr: u64) -> Option<SymbolHit> {
        self.module_at(addr)?;
        self.symbols()?.lookup_addr(addr)
    }

    fn describe(&mut self, addr: u64) -> String {
        if let Some(m) = self.module_at(addr).cloned() {
            if let Some(s) = self.symbolize(addr) {
                return s;
            }
            return match m.section_at(addr) {
                Some(sec) => format!("{}!{}+0x{:x}", m.name, sec.name, addr - sec.base),
                None => format!("{}+0x{:x}", m.name, addr - m.base),
            };
        }
        match self.map.find(addr) {
            Some(r) if r.kind == MemKind::Image || r.label.is_some() => self.region_label(r),
            Some(r) => format!("{} {}", r.kind, r.protect),
            None => "unmapped".into(),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.suspended {
            let _ = self.proc.resume();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(name_matches("notepad", "Notepad.exe"));
        assert!(name_matches("note*", "notepad.exe"));
        assert!(name_matches("*.exe", "a.exe"));
        assert!(name_matches("n?tepad.exe", "notepad.exe"));
        assert!(!name_matches("note", "notepad.exe"));
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_number("0x10"), Some(16));
        assert_eq!(parse_number("10"), Some(10));
        assert_eq!(parse_number("7ff6a0"), Some(0x7ff6a0));
        assert_eq!(parse_number("00007ff6`12345678"), Some(0x7ff6_1234_5678));
        assert_eq!(parse_number("xyz"), None);
    }
}
