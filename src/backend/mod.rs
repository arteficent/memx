use anyhow::Result;

use crate::model::{DumpReport, Module, ProcessExtras, ProcessInfo, ProcessSummary, Region, SymbolHit, ThreadInfo};

#[cfg(windows)]
pub mod windows;

#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub debug_privilege: bool,
    pub suspend_access: bool,
}

pub trait ProcessBackend {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>>;
    fn list_catalog(&self) -> Result<Vec<ProcessSummary>> {
        Ok(self.list_processes()?.into_iter().map(|info| ProcessSummary {
            info,
            session_id: None,
            owner: None,
            category: "unknown".into(),
            access: "unknown".into(),
        }).collect())
    }
    fn open(&self, pid: u32, opts: &OpenOptions) -> Result<Box<dyn Process>>;
}

/// An opened target process. All access is read-only.
pub trait Process {
    fn info(&self) -> &ProcessInfo;
    fn pointer_size(&self) -> usize;
    fn regions(&self) -> Result<Vec<Region>>;
    /// Loaded modules (sections are filled in by the caller from PE headers).
    fn modules(&self) -> Result<Vec<Module>>;
    fn threads(&self) -> Result<Vec<ThreadInfo>>;
    fn extras(&self) -> Result<ProcessExtras>;
    fn mapped_file_name(&self, addr: u64) -> Option<String>;
    /// Reads up to `buf.len()` bytes; returns the number of bytes actually read (0 on failure).
    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> usize;
    fn load_symbols(&self, search_path: Option<&str>, modules: &[Module]) -> Result<Box<dyn SymbolProvider>>;
    fn suspend(&self) -> Result<()>;
    fn resume(&self) -> Result<()>;
    fn dump(&self, _path: &std::path::Path) -> Result<DumpReport> {
        anyhow::bail!("process snapshot dumps are not supported by this backend")
    }
}

pub trait SymbolProvider {
    fn lookup_addr(&self, addr: u64) -> Option<SymbolHit>;
    fn lookup_name(&self, name: &str) -> Option<SymbolHit>;
    fn globals(&self, module_base: u64, mask: &str) -> Vec<SymbolHit>;
}

pub fn native() -> Result<Box<dyn ProcessBackend>> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WindowsBackend))
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("this platform is not supported yet (Windows only)")
    }
}
