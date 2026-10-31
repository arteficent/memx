use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use windows_sys::Win32::Foundation::{FILETIME, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IsProcessSnapshotCallback, MiniDumpIgnoreInaccessibleMemory, MiniDumpWithFullMemory,
    MiniDumpWithFullMemoryInfo, MiniDumpWithThreadInfo, MiniDumpWriteDump,
    MINIDUMP_CALLBACK_INFORMATION, MINIDUMP_CALLBACK_INPUT, MINIDUMP_CALLBACK_OUTPUT,
};
use windows_sys::Win32::System::Diagnostics::ProcessSnapshotting::{
    PssCaptureSnapshot, PssFreeSnapshot, HPSS, PSS_CAPTURE_THREADS,
    PSS_CAPTURE_THREAD_CONTEXT, PSS_CAPTURE_VA_CLONE, PSS_CAPTURE_VA_SPACE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_CREATE_PROCESS,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use super::{last_error, OwnedHandle, WinProcess};
use crate::model::DumpReport;

struct Snapshot(HPSS);

impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe { PssFreeSnapshot(GetCurrentProcess(), self.0) };
    }
}

struct Destination {
    file: Option<File>,
    path: PathBuf,
    complete: bool,
}

impl Drop for Destination {
    fn drop(&mut self) {
        self.file.take();
        if !self.complete {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn timestamp() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?)
}

fn creation_time(process: HANDLE) -> Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(last_error("GetProcessTimes"));
    }
    Ok((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64)
}

unsafe extern "system" fn callback(_context: *mut c_void, input: *const MINIDUMP_CALLBACK_INPUT, output: *mut MINIDUMP_CALLBACK_OUTPUT) -> i32 {
    if input.is_null() || output.is_null() { return 0; }
    if std::ptr::read_unaligned(input).CallbackType == IsProcessSnapshotCallback as u32 {
        (*output).Anonymous.Status = 1;
    }
    1
}

pub(super) fn write(process: &WinProcess, path: &Path) -> Result<DumpReport> {
    if !path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("dmp")) {
        bail!("dump destination must end in .dmp");
    }
    let path = std::path::absolute(path)?;
    let target = OwnedHandle::new(unsafe { OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE,
        0, process.info.pid,
    ) }).ok_or_else(|| last_error("OpenProcess(snapshot access); run elevated if authorized; PP/PPL restrictions still apply"))?;
    if creation_time(process.h())? != creation_time(target.0)? {
        bail!("the selected process exited and its PID was reused; select it again");
    }
    let file = OpenOptions::new().read(true).write(true).create_new(true).open(&path)
        .with_context(|| format!("creating {} (existing files are never overwritten)", path.display()))?;
    let mut destination = Destination { file: Some(file), path: path.clone(), complete: false };
    let capture_started_unix_ms = timestamp()?;
    let mut snapshot = std::ptr::null_mut();
    let context_flags = if process.wow64 { 0x0001_003F } else { 0x0010_003F };
    let status = unsafe { PssCaptureSnapshot(target.0,
        PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,
        context_flags, &mut snapshot,
    ) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32)).context("PssCaptureSnapshot failed; no non-atomic live-dump fallback was used");
    }
    let snapshot = Snapshot(snapshot);
    let capture_completed_unix_ms = timestamp()?;
    let callbacks = MINIDUMP_CALLBACK_INFORMATION { CallbackRoutine: Some(callback), CallbackParam: std::ptr::null_mut() };
    let file = destination.file.as_ref().ok_or_else(|| anyhow!("dump file is closed"))?;
    let _guard = super::dbghelp_lock();
    let success = unsafe { MiniDumpWriteDump(snapshot.0, process.info.pid, file.as_raw_handle(),
        MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo | MiniDumpIgnoreInaccessibleMemory,
        std::ptr::null(), std::ptr::null(), &callbacks,
    ) };
    if success == 0 { return Err(last_error("MiniDumpWriteDump")); }
    file.sync_all().context("flushing process dump")?;
    let bytes = file.metadata()?.len();
    let finished_unix_ms = timestamp()?;
    destination.complete = true;
    Ok(DumpReport {
        pid: process.info.pid, path: path.display().to_string(), bytes,
        capture_started_unix_ms, capture_completed_unix_ms, finished_unix_ms,
        mode: "pss_full_memory",
        warnings: vec![
            "Contains accessible user-mode memory, not kernel, PP/PPL, or unreadable pages.".into(),
            "Private clone pages reflect the capture interval; shared/mapped memory is not globally atomic.".into(),
            "Dump files may contain credentials and other secrets; restrict access to the destination directory.".into(),
        ],
    })
}