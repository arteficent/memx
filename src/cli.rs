use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "memx", version, about = "Lightweight, read-only process memory inspector")]
pub struct Cli {
    /// Emit JSON instead of tables.
    #[arg(long, global = true)]
    pub json: bool,
    /// Write output to a file instead of stdout (memory may contain secrets).
    #[arg(long, global = true, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Symbol search path, e.g. `C:\symbols;C:\myapp\pdb` (defaults to _NT_SYMBOL_PATH).
    #[arg(long, global = true, value_name = "PATH")]
    pub symbols: Option<String>,
    /// Disable debug-symbol loading.
    #[arg(long, global = true)]
    pub no_symbols: bool,
    /// Require SeDebugPrivilege (automatically attempted when elevated; does not bypass PP/PPL).
    #[arg(long, global = true)]
    pub debug_priv: bool,
    /// Suspend the target while inspecting it (resumed on exit or Ctrl+C).
    #[arg(long, global = true)]
    pub suspend: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone)]
#[group(required = true, multiple = false)]
pub struct Target {
    /// Target process id.
    #[arg(short, long)]
    pub pid: Option<u32>,
    /// Target process name (case-insensitive, `.exe` optional, `*`/`?` globs allowed).
    #[arg(short, long)]
    pub name: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Capture accessible user-mode memory using Windows Process Snapshotting.
    Dump {
        #[command(flatten)]
        target: Target,
        /// New .dmp destination; existing files are never overwritten.
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
    },
    /// Manage opt-in administrator sign-in startup (not a kernel/boot driver).
    Startup {
        #[command(subcommand)]
        action: StartupAction,
    },
    /// List running processes.
    Ps {
        /// Name filter (glob).
        #[arg(short, long)]
        filter: Option<String>,
    },
    /// List memory regions of a process.
    Regions {
        #[command(flatten)]
        target: Target,
        /// Include free (unallocated) ranges.
        #[arg(long)]
        all: bool,
        /// Only committed regions.
        #[arg(long)]
        committed: bool,
        /// Only readable regions.
        #[arg(long)]
        readable: bool,
        /// Only writable regions.
        #[arg(long)]
        writable: bool,
        /// Only executable regions.
        #[arg(long)]
        exec: bool,
        /// Only this region type.
        #[arg(long, value_parser = ["image", "mapped", "private"])]
        kind: Option<String>,
        /// Only regions whose label contains this text.
        #[arg(long)]
        label: Option<String>,
    },
    /// List loaded modules.
    Modules {
        #[command(flatten)]
        target: Target,
        /// Also list PE sections.
        #[arg(long)]
        sections: bool,
    },
    /// List threads with their TEB and stack ranges.
    Threads {
        #[command(flatten)]
        target: Target,
    },
    /// Read memory as hex or as an explicit type.
    Read {
        #[command(flatten)]
        target: Target,
        /// Address: 0x…, decimal, module, module+0x10, module!symbol.
        #[arg(short, long)]
        addr: String,
        /// Number of bytes to read.
        #[arg(short, long, default_value_t = 256)]
        len: usize,
        /// Type to decode as, optionally with a count: u32, f64[4], cstr, wstr, ptr, guid, ...
        #[arg(long = "as", value_name = "TYPE")]
        as_type: Option<String>,
    },
    /// Auto-typed annotated view (symbols > RTTI > heuristics).
    Inspect {
        #[command(flatten)]
        target: Target,
        /// Address: 0x…, decimal, module, module+0x10, module!symbol.
        #[arg(short, long)]
        addr: String,
        /// Number of bytes to inspect.
        #[arg(short, long, default_value_t = 256)]
        len: usize,
    },
    /// Resolve a symbol to an address or an address to a symbol.
    Symbol {
        #[command(flatten)]
        target: Target,
        /// `module!name` or an address.
        query: String,
    },
    /// List global variables of a module (needs its PDB).
    Globals {
        #[command(flatten)]
        target: Target,
        /// Module name, e.g. `myapp.exe`.
        #[arg(short, long)]
        module: String,
        /// Symbol name mask (DbgHelp wildcards).
        #[arg(short, long, default_value = "*")]
        filter: String,
    },
    /// Search readable memory for a value or pattern.
    Search {
        #[command(flatten)]
        target: Target,
        #[command(flatten)]
        pattern: Pattern,
        /// Only report addresses aligned to the value size.
        #[arg(long)]
        aligned: bool,
        /// Maximum number of hits.
        #[arg(long, default_value_t = 100)]
        max: usize,
    },
    /// Interactive terminal UI.
    #[cfg(feature = "tui")]
    Tui {
        #[command(flatten)]
        target: Target,
        /// Initial address.
        #[arg(short, long)]
        addr: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum StartupAction {
    /// Show current-user scheduled startup and legacy entry status.
    Status,
    /// Launch the installed executable elevated at user sign-in (requires admin).
    Enable {
        #[arg(long, value_name = "EXE")]
        executable: PathBuf,
    },
    /// Remove memx scheduled and legacy startup entries (requires admin).
    Disable,
}

#[derive(Args, Debug, Clone)]
#[group(required = true, multiple = false)]
pub struct Pattern {
    /// ASCII/UTF-8 string.
    #[arg(long)]
    pub string: Option<String>,
    /// UTF-16LE string.
    #[arg(long)]
    pub wstring: Option<String>,
    /// Hex bytes, `??` = wildcard: "de ad ?? ef".
    #[arg(long)]
    pub hex: Option<String>,
    #[arg(long)]
    pub u32: Option<u32>,
    #[arg(long, allow_negative_numbers = true)]
    pub i32: Option<i32>,
    #[arg(long)]
    pub u64: Option<u64>,
    #[arg(long, allow_negative_numbers = true)]
    pub i64: Option<i64>,
    #[arg(long, allow_negative_numbers = true)]
    pub f32: Option<f32>,
    #[arg(long, allow_negative_numbers = true)]
    pub f64: Option<f64>,
}

impl Pattern {
    /// Returns (pattern, natural alignment).
    pub fn bytes(&self) -> anyhow::Result<(Vec<Option<u8>>, usize)> {
        let lit = |b: Vec<u8>| b.into_iter().map(Some).collect::<Vec<_>>();
        Ok(if let Some(s) = &self.string {
            (lit(s.as_bytes().to_vec()), 1)
        } else if let Some(s) = &self.wstring {
            (lit(s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()), 2)
        } else if let Some(h) = &self.hex {
            (crate::search::parse_hex_pattern(h)?, 1)
        } else if let Some(v) = self.u32 {
            (lit(v.to_le_bytes().to_vec()), 4)
        } else if let Some(v) = self.i32 {
            (lit(v.to_le_bytes().to_vec()), 4)
        } else if let Some(v) = self.u64 {
            (lit(v.to_le_bytes().to_vec()), 8)
        } else if let Some(v) = self.i64 {
            (lit(v.to_le_bytes().to_vec()), 8)
        } else if let Some(v) = self.f32 {
            (lit(v.to_le_bytes().to_vec()), 4)
        } else if let Some(v) = self.f64 {
            (lit(v.to_le_bytes().to_vec()), 8)
        } else {
            anyhow::bail!("no search pattern given")
        })
    }
}

pub fn execute(cli: &Cli) -> anyhow::Result<()> {
    use std::io::Write;
    use anyhow::Context;

    if matches!(cli.command, Command::Dump { .. }) && (cli.out.is_some() || cli.suspend) {
        anyhow::bail!("dump uses --file; --out and --suspend are not supported with snapshot dumps");
    }
    let backend = crate::backend::native()?;
    let mut out: Box<dyn Write> = match &cli.out {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?)),
        None => Box::new(std::io::BufWriter::new(std::io::stdout().lock())),
    };
    crate::commands::run(&mut crate::commands::Ctx { cli, backend: &*backend, out: &mut *out })?;
    out.flush()?;
    Ok(())
}

pub fn entry() -> std::process::ExitCode {
    match execute(&Cli::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe) {
                return std::process::ExitCode::SUCCESS;
            }
            eprintln!("error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
