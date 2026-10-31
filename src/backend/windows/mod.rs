mod ffi;
mod dump;
mod symbols;

use std::ffi::c_void;
use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use windows_sys::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE, HMODULE,
    INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, IsWellKnownSid, LookupAccountSidW,
    LookupPrivilegeValueW, TokenElevation, TokenUser, WinLocalServiceSid, WinLocalSystemSid,
    WinNetworkServiceSid,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    MEM_RESERVE,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetMappedFileNameW, GetModuleFileNameExW, GetModuleInformation,
    LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessInformation, IsWow64Process2, OpenProcess, OpenProcessToken,
    OpenThread, ProcessProtectionLevelInfo, QueryFullProcessImageNameW,
    PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_VM_READ,
    THREAD_QUERY_LIMITED_INFORMATION,
};

use super::{OpenOptions, Process, ProcessBackend, SymbolProvider};
use crate::model::{
    MemKind, MemState, Module, ProcessExtras, ProcessInfo, ProcessSummary, Protect, Region, StackRange, ThreadInfo,
};

const PROTECTION_LEVEL_NONE: u32 = 0xFFFF_FFFE;
const HOST_POINTER_SIZE: usize = size_of::<usize>();
static DBGHELP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn dbghelp_lock() -> std::sync::MutexGuard<'static, ()> {
    DBGHELP_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn from_wide(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

fn last_error(api: &str) -> anyhow::Error {
    anyhow!("{api} failed: {}", std::io::Error::last_os_error())
}

/// Rejects ranges that a 32-bit host cannot address instead of truncating them.
fn host_ptr(addr: u64, len: usize) -> Option<*const c_void> {
    let last = addr.checked_add(len.saturating_sub(1) as u64)?;
    (last <= usize::MAX as u64).then_some(addr as usize as *const c_void)
}

pub(crate) struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    fn new(h: HANDLE) -> Option<Self> {
        (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(Self(h))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub struct WindowsBackend;

impl ProcessBackend for WindowsBackend {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        let snap = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
            .ok_or_else(|| last_error("CreateToolhelp32Snapshot"))?;
        let mut out = Vec::new();
        let mut e: PROCESSENTRY32W = unsafe { zeroed() };
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = unsafe { Process32FirstW(snap.0, &mut e) } != 0;
        while ok {
            out.push(ProcessInfo {
                pid: e.th32ProcessID,
                ppid: e.th32ParentProcessID,
                name: from_wide(&e.szExeFile),
                threads: e.cntThreads,
                path: None,
                pointer_size: None,
            });
            ok = unsafe { Process32NextW(snap.0, &mut e) } != 0;
        }
        Ok(out)
    }

    fn list_catalog(&self) -> Result<Vec<ProcessSummary>> {
        configure_debug_privilege(false, current_process_is_elevated().unwrap_or(false), enable_debug_privilege)?;
        let sessions = system_process_sessions().unwrap_or_default();
        let mut catalog = Vec::new();
        for mut info in self.list_processes()? {
            let session_id = sessions.get(&info.pid).copied().or_else(|| {
                let mut session = 0;
                (unsafe { ProcessIdToSessionId(info.pid, &mut session) } != 0).then_some(session)
            });
            let query = OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, info.pid) });
            let mut owner = None;
            let mut system_account = false;
            let mut protected = false;
            if let Some(handle) = &query {
                info.pointer_size = target_pointer_size(handle.0);
                info.path = process_path(handle.0);
                protected = is_protected(handle.0);
                (owner, system_account) = process_owner(handle.0);
            }
            let category = if info.pid <= 4 || system_account || session_id == Some(0) {
                "system"
            } else if session_id.is_some() {
                "user"
            } else { "unknown" };
            let access = if protected {
                "protected"
            } else if info.pointer_size.is_some_and(|size| usize::from(size) > HOST_POINTER_SIZE) {
                "x64_required"
            } else {
                let read = OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, info.pid) });
                if read.is_some() { "readable" }
                else if unsafe { GetLastError() } == ERROR_ACCESS_DENIED { "denied" }
                else { "unavailable" }
            };
            catalog.push(ProcessSummary { info, session_id, owner, category: category.into(), access: access.into() });
        }
        catalog.sort_by_key(|process| process.info.pid);
        Ok(catalog)
    }

    fn open(&self, pid: u32, opts: &OpenOptions) -> Result<Box<dyn Process>> {
        let debug_enabled = configure_debug_privilege(
            opts.debug_privilege,
            current_process_is_elevated().unwrap_or(false),
            enable_debug_privilege,
        )?;
        let extra = if opts.suspend_access { PROCESS_SUSPEND_RESUME } else { 0 };
        let mut full_query = true;
        let mut h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | extra, 0, pid) };
        if h.is_null() {
            full_query = false;
            h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | extra, 0, pid) };
        }
        if h.is_null() {
            let err = unsafe { GetLastError() };
            if err == ERROR_INVALID_PARAMETER {
                bail!("no running process with pid {pid}");
            }
            if err == ERROR_ACCESS_DENIED {
                let protected = OwnedHandle::new(unsafe {
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
                })
                .is_some_and(|handle| is_protected(handle.0));
                return Err(process_access_denied(pid, protected, debug_enabled));
            }
            return Err(last_error("OpenProcess"));
        }
        let handle = OwnedHandle(h);

        let pointer_size = target_pointer_size(h).ok_or_else(|| anyhow!("cannot determine target architecture for pid {pid} (x64 and x86/WOW64 targets are supported)"))?;
        if usize::from(pointer_size) > HOST_POINTER_SIZE {
            bail!("pid {pid} is a 64-bit process; inspect it with the x64 memx build (this x86 build supports 32-bit targets)");
        }
        let wow64 = pointer_size == 4;
        let path = process_path(h);

        let listed = self.list_processes()?.into_iter().find(|p| p.pid == pid);
        let name = listed
            .as_ref()
            .map(|p| p.name.clone())
            .or_else(|| path.as_deref().and_then(|p| p.rsplit('\\').next()).map(str::to_string))
            .unwrap_or_default();
        let info = ProcessInfo {
            pid,
            ppid: listed.as_ref().map_or(0, |p| p.ppid),
            name,
            threads: listed.as_ref().map_or(0, |p| p.threads),
            path,
            pointer_size: Some(pointer_size),
        };
        Ok(Box::new(WinProcess { handle, info, wow64, full_query }))
    }
}

fn system_process_sessions() -> Result<HashMap<u32, u32>> {
    use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

    let mut capacity = 256 * 1024usize;
    for _ in 0..8 {
        if capacity > 64 * 1024 * 1024 {
            bail!("system process metadata exceeds allocation limit");
        }
        let mut buffer = vec![0usize; capacity.div_ceil(size_of::<usize>())];
        let mut needed = 0;
        let status = unsafe { NtQuerySystemInformation(SystemProcessInformation, buffer.as_mut_ptr().cast(), capacity as u32, &mut needed) };
        if matches!(status as u32, 0xC000_0004 | 0xC000_0023) {
            capacity = (needed as usize + 65536).max(capacity * 2);
            continue;
        }
        if status < 0 {
            bail!("NtQuerySystemInformation failed: NTSTATUS 0x{:08x}", status as u32);
        }
        let used = needed as usize;
        if used > capacity {
            bail!("invalid system process metadata length");
        }
        let mut sessions = HashMap::new();
        let mut offset = 0usize;
        loop {
            if offset.checked_add(size_of::<SYSTEM_PROCESS_INFORMATION>()).is_none_or(|end| end > used) {
                bail!("truncated system process metadata");
            }
            let process = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u8>().add(offset).cast::<SYSTEM_PROCESS_INFORMATION>()) };
            sessions.insert(process.UniqueProcessId as usize as u32, process.SessionId);
            if process.NextEntryOffset == 0 { return Ok(sessions); }
            let next = process.NextEntryOffset as usize;
            if next < size_of::<SYSTEM_PROCESS_INFORMATION>() {
                bail!("invalid system process metadata offset");
            }
            offset = offset.checked_add(next).ok_or_else(|| anyhow!("system process metadata overflow"))?;
        }
    }
    bail!("system process list changed too often; refresh to retry")
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn system_snapshot_supplies_sessions_without_memory_handles() {
        let sessions = system_process_sessions().unwrap();
        assert_eq!(sessions.get(&4), Some(&0));
        assert!(sessions.contains_key(&std::process::id()));
    }
}

fn target_pointer_size(handle: HANDLE) -> Option<u8> {
    let mut process_machine = 0;
    let mut native_machine = 0;
    if unsafe { IsWow64Process2(handle, &mut process_machine, &mut native_machine) } == 0 {
        return None;
    }
    match (process_machine, native_machine) {
        (0x014c, _) | (0, 0x014c) => Some(4),
        (0, 0x8664) | (0x8664, _) => Some(8),
        _ => None,
    }
}

fn process_path(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    (unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) } != 0)
        .then(|| String::from_utf16_lossy(&buffer[..len as usize]))
}

fn process_owner(handle: HANDLE) -> (Option<String>, bool) {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) } == 0 {
        return (None, false);
    }
    let token = OwnedHandle(token);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return (None, false);
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe { GetTokenInformation(token.0, TokenUser, buffer.as_mut_ptr().cast(), needed, &mut needed) } == 0 {
        return (None, false);
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let system = [WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid].iter()
        .any(|kind| unsafe { IsWellKnownSid(user.User.Sid, *kind) } != 0);
    let (mut name, mut domain) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut name_len, mut domain_len, mut usage) = (256, 256, 0);
    if unsafe { LookupAccountSidW(std::ptr::null(), user.User.Sid, name.as_mut_ptr(), &mut name_len, domain.as_mut_ptr(), &mut domain_len, &mut usage) } == 0 {
        return (None, system);
    }
    let name = from_wide(&name);
    let domain = from_wide(&domain);
    (Some(if domain.is_empty() { name } else { format!("{domain}\\{name}") }), system)
}

fn configure_debug_privilege(
    requested: bool,
    elevated: bool,
    enable: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    if !requested && !elevated {
        return Ok(false);
    }
    match enable() {
        Ok(()) => Ok(true),
        Err(error) if requested => {
            Err(error).context("enabling SeDebugPrivilege (run from an elevated prompt)")
        }
        Err(_) => Ok(false),
    }
}

pub(crate) fn current_process_is_elevated() -> Result<bool> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    let token = OwnedHandle(token);
    let mut elevation: TOKEN_ELEVATION = unsafe { zeroed() };
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0 {
        return Err(last_error("GetTokenInformation(TokenElevation)"));
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn process_access_denied(pid: u32, protected: bool, debug_enabled: bool) -> anyhow::Error {
    if protected {
        anyhow!("pid {pid}: access denied - Windows protected process (PP/PPL); administrator rights and SeDebugPrivilege do not grant memory-read access")
    } else if debug_enabled {
        anyhow!("pid {pid}: access denied even with SeDebugPrivilege enabled; Windows protection or security policy may prohibit memory-read access")
    } else {
        anyhow!("pid {pid}: access denied - run from an elevated prompt; memx automatically attempts SeDebugPrivilege there, or use --debug-priv to require it; PP/PPL restrictions still apply")
    }
}

fn is_protected(h: HANDLE) -> bool {
    let mut info: PROCESS_PROTECTION_LEVEL_INFORMATION = unsafe { zeroed() };
    let ok = unsafe {
        GetProcessInformation(
            h,
            ProcessProtectionLevelInfo,
            &mut info as *mut _ as *mut c_void,
            size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        )
    } != 0;
    ok && info.ProtectionLevel != PROTECTION_LEVEL_NONE
}

fn enable_debug_privilege() -> Result<()> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    let token = OwnedHandle(token);
    let mut luid = LUID { LowPart: 0, HighPart: 0 };
    let name = wide("SeDebugPrivilege");
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(last_error("LookupPrivilegeValueW"));
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    let ok = unsafe { AdjustTokenPrivileges(token.0, 0, &tp, 0, null_mut(), null_mut()) } != 0;
    // AdjustTokenPrivileges "succeeds" with ERROR_NOT_ALL_ASSIGNED when the privilege is not held.
    if !ok || unsafe { GetLastError() } != 0 {
        bail!("SeDebugPrivilege is not available to this user");
    }
    Ok(())
}

static SUSPENDED_HANDLE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn ctrl_handler(_ctrl: u32) -> i32 {
    let h = SUSPENDED_HANDLE.swap(0, Ordering::SeqCst);
    if h != 0 {
        ffi::NtResumeProcess(h as HANDLE);
    }
    0
}

pub struct WinProcess {
    handle: OwnedHandle,
    info: ProcessInfo,
    wow64: bool,
    full_query: bool,
}

impl WinProcess {
    fn h(&self) -> HANDLE {
        self.handle.0
    }

    fn read_u32(&self, addr: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        (self.read_raw(addr, &mut b) == 4).then(|| u32::from_le_bytes(b))
    }

    fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        (self.read_raw(addr, &mut b) == 8).then(|| u64::from_le_bytes(b))
    }

    /// NT_TIB32: StackBase @ +4, StackLimit @ +8.
    fn stack32(&self, teb32: u64, wow64: bool) -> Option<StackRange> {
        let (base, limit) = (self.read_u32(teb32 + 4)?, self.read_u32(teb32 + 8)?);
        (limit != 0 && limit < base).then_some(StackRange { base: base as u64, limit: limit as u64, wow64 })
    }

    fn heaps32(&self, peb32: u64, heaps: &mut Vec<u64>) {
        // PEB32: NumberOfHeaps @ +0x88, ProcessHeaps @ +0x90
        if let (Some(n), Some(arr)) = (self.read_u32(peb32 + 0x88), self.read_u32(peb32 + 0x90)) {
            for i in 0..n.min(1024) as u64 {
                if let Some(h) = self.read_u32(arr as u64 + i * 4) {
                    heaps.push(h as u64);
                }
            }
        }
    }

    fn thread_stacks(&self, teb: u64) -> Vec<StackRange> {
        if HOST_POINTER_SIZE == 4 {
            // WOW64 may report either the TEB32 or the TEB64 (TEB32 follows it by 0x2000).
            return [teb, teb + 0x2000].into_iter().find_map(|teb32| self.stack32(teb32, false)).into_iter().collect();
        }
        let mut out = Vec::new();
        // NT_TIB64: StackBase @ +0x08, StackLimit @ +0x10
        if let (Some(base), Some(limit)) = (self.read_u64(teb + 8), self.read_u64(teb + 0x10)) {
            if limit != 0 && limit < base {
                out.push(StackRange { base, limit, wow64: false });
            }
        }
        if self.wow64 {
            // The 32-bit TEB sits 0x2000 after the 64-bit one.
            out.extend(self.stack32(teb + 0x2000, true));
        }
        out
    }
}

impl Process for WinProcess {
    fn dump(&self, path: &std::path::Path) -> Result<crate::model::DumpReport> {
        dump::write(self, path)
    }

    fn info(&self) -> &ProcessInfo {
        &self.info
    }

    fn pointer_size(&self) -> usize {
        if self.wow64 { 4 } else { 8 }
    }

    fn regions(&self) -> Result<Vec<Region>> {
        let mut si: SYSTEM_INFO = unsafe { zeroed() };
        unsafe { GetSystemInfo(&mut si) };
        let mut addr = si.lpMinimumApplicationAddress as u64;
        let max = si.lpMaximumApplicationAddress as u64;
        let mut out = Vec::new();
        while addr < max {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let Some(query) = host_ptr(addr, 1) else { break };
            let n = unsafe {
                VirtualQueryEx(self.h(), query, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>())
            };
            if n == 0 {
                if out.is_empty() {
                    return Err(last_error("VirtualQueryEx"));
                }
                break;
            }
            let base = mbi.BaseAddress as u64;
            let size = mbi.RegionSize as u64;
            let state = match mbi.State {
                MEM_COMMIT => MemState::Commit,
                MEM_RESERVE => MemState::Reserve,
                _ => MemState::Free,
            };
            let kind = match mbi.Type {
                MEM_IMAGE => MemKind::Image,
                MEM_MAPPED => MemKind::Mapped,
                MEM_PRIVATE => MemKind::Private,
                _ => MemKind::None,
            };
            out.push(Region {
                base,
                size,
                state,
                protect: Protect(mbi.Protect),
                alloc_base: mbi.AllocationBase as u64,
                alloc_protect: Protect(mbi.AllocationProtect),
                kind,
                label: None,
            });
            let next = base.saturating_add(size);
            if next <= addr {
                break;
            }
            addr = next;
        }
        Ok(out)
    }

    fn modules(&self) -> Result<Vec<Module>> {
        if !self.full_query {
            bail!("module list needs PROCESS_QUERY_INFORMATION access");
        }
        let mut mods: Vec<HMODULE> = vec![null_mut(); 512];
        let mut attempts = 0;
        loop {
            let mut needed = 0u32;
            let cb = (mods.len() * size_of::<HMODULE>()) as u32;
            if unsafe { EnumProcessModulesEx(self.h(), mods.as_mut_ptr(), cb, &mut needed, LIST_MODULES_ALL) } == 0 {
                attempts += 1;
                if attempts < 3 {
                    continue;
                }
                return Err(last_error("EnumProcessModulesEx"));
            }
            let n = needed as usize / size_of::<HMODULE>();
            if n > mods.len() {
                mods.resize(n, null_mut());
                continue;
            }
            mods.truncate(n);
            break;
        }
        let mut out = Vec::with_capacity(mods.len());
        for hm in mods {
            let mut mi: MODULEINFO = unsafe { zeroed() };
            if unsafe { GetModuleInformation(self.h(), hm, &mut mi, size_of::<MODULEINFO>() as u32) } == 0 {
                continue;
            }
            let mut buf = vec![0u16; 1024];
            let n = unsafe { GetModuleFileNameExW(self.h(), hm, buf.as_mut_ptr(), buf.len() as u32) };
            let path = String::from_utf16_lossy(&buf[..n as usize]);
            let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
            out.push(Module {
                name,
                base: mi.lpBaseOfDll as u64,
                size: mi.SizeOfImage as u64,
                path,
                sections: Vec::new(),
                export_dir: None,
            });
        }
        out.sort_by_key(|m| m.base);
        Ok(out)
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        let snap = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })
            .ok_or_else(|| last_error("CreateToolhelp32Snapshot"))?;
        let mut e: THREADENTRY32 = unsafe { zeroed() };
        e.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut out = Vec::new();
        let mut ok = unsafe { Thread32First(snap.0, &mut e) } != 0;
        while ok {
            if e.th32OwnerProcessID == self.info.pid {
                let tid = e.th32ThreadID;
                let mut teb = 0u64;
                if let Some(th) = OwnedHandle::new(unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid) }) {
                    let mut tbi = ffi::ThreadBasicInformation::default();
                    let status = unsafe {
                        ffi::NtQueryInformationThread(
                            th.0,
                            ffi::THREAD_BASIC_INFORMATION_CLASS,
                            &mut tbi as *mut _ as *mut c_void,
                            size_of::<ffi::ThreadBasicInformation>() as u32,
                            null_mut(),
                        )
                    };
                    if status >= 0 {
                        teb = tbi.teb as u64;
                    }
                }
                let stacks = if teb != 0 { self.thread_stacks(teb) } else { Vec::new() };
                out.push(ThreadInfo { tid, teb, stacks });
            }
            ok = unsafe { Thread32Next(snap.0, &mut e) } != 0;
        }
        Ok(out)
    }

    fn extras(&self) -> Result<ProcessExtras> {
        let mut ex = ProcessExtras::default();
        let mut pbi = ffi::ProcessBasicInformation::default();
        let status = unsafe {
            ffi::NtQueryInformationProcess(
                self.h(),
                ffi::PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut c_void,
                size_of::<ffi::ProcessBasicInformation>() as u32,
                null_mut(),
            )
        };
        if status < 0 {
            bail!("NtQueryInformationProcess failed: 0x{:08x}", status as u32);
        }
        let peb = pbi.peb as u64;
        if peb != 0 && HOST_POINTER_SIZE == 4 {
            ex.peb = Some(peb);
            self.heaps32(peb, &mut ex.heaps);
        } else if peb != 0 {
            ex.peb = Some(peb);
            // PEB64: NumberOfHeaps @ +0xE8, ProcessHeaps @ +0xF0
            if let (Some(n), Some(arr)) = (self.read_u32(peb + 0xE8), self.read_u64(peb + 0xF0)) {
                for i in 0..n.min(1024) as u64 {
                    if let Some(h) = self.read_u64(arr + i * 8) {
                        ex.heaps.push(h);
                    }
                }
            }
        }
        if self.wow64 && HOST_POINTER_SIZE == 8 {
            let mut peb32: usize = 0;
            let status = unsafe {
                ffi::NtQueryInformationProcess(
                    self.h(),
                    ffi::PROCESS_WOW64_INFORMATION_CLASS,
                    &mut peb32 as *mut _ as *mut c_void,
                    size_of::<usize>() as u32,
                    null_mut(),
                )
            };
            if status >= 0 && peb32 != 0 {
                let peb32 = peb32 as u64;
                ex.peb32 = Some(peb32);
                self.heaps32(peb32, &mut ex.heaps);
            }
        }
        Ok(ex)
    }

    fn mapped_file_name(&self, addr: u64) -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let n = unsafe { GetMappedFileNameW(self.h(), host_ptr(addr, 1)?, buf.as_mut_ptr(), buf.len() as u32) };
        (n > 0).then(|| String::from_utf16_lossy(&buf[..n as usize]))
    }

    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> usize {
        let Some(source) = host_ptr(addr, buf.len()).filter(|_| !buf.is_empty()) else {
            return 0;
        };
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(self.h(), source, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut read)
        } != 0;
        if ok { buf.len() } else { read.min(buf.len()) }
    }

    fn load_symbols(&self, search_path: Option<&str>, modules: &[Module]) -> Result<Box<dyn SymbolProvider>> {
        Ok(Box::new(symbols::DbgHelp::new(self.h(), search_path, modules)?))
    }

    fn suspend(&self) -> Result<()> {
        let status = unsafe { ffi::NtSuspendProcess(self.h()) };
        if status < 0 {
            bail!("NtSuspendProcess failed: 0x{:08x}", status as u32);
        }
        SUSPENDED_HANDLE.store(self.h() as usize, Ordering::SeqCst);
        unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
        Ok(())
    }

    fn resume(&self) -> Result<()> {
        SUSPENDED_HANDLE.store(0, Ordering::SeqCst);
        let status = unsafe { ffi::NtResumeProcess(self.h()) };
        if status < 0 {
            bail!("NtResumeProcess failed: 0x{:08x}", status as u32);
        }
        Ok(())
    }
}

#[cfg(test)]
mod access_tests {
    use super::*;

    #[test]
    fn debug_privilege_policy() {
        let skipped = configure_debug_privilege(false, false, || {
            panic!("a non-elevated default session must not enable debug privilege")
        });
        assert!(!skipped.unwrap());
        assert!(configure_debug_privilege(false, true, || Ok(())).unwrap());
        assert!(configure_debug_privilege(true, false, || Ok(())).unwrap());
        assert!(configure_debug_privilege(true, true, || Ok(())).unwrap());
        assert!(!configure_debug_privilege(false, true, || Err(anyhow!("not assigned"))).unwrap());
        let error = configure_debug_privilege(true, false, || Err(anyhow!("not assigned")))
            .unwrap_err();
        assert!(format!("{error:#}").contains("not assigned"));
    }

    #[test]
    fn elevation_query_succeeds_for_current_process() {
        current_process_is_elevated().unwrap();
    }

    #[test]
    fn denied_access_explains_the_actual_limit() {
        let protected = process_access_denied(1234, true, true).to_string();
        assert!(protected.contains("PP/PPL"));
        assert!(protected.contains("do not grant memory-read access"));
        let privileged = process_access_denied(1234, false, true).to_string();
        assert!(privileged.contains("SeDebugPrivilege enabled"));
        assert!(!privileged.contains("run from an elevated prompt"));
        let ordinary = process_access_denied(1234, false, false).to_string();
        assert!(ordinary.contains("run from an elevated prompt"));
        assert!(ordinary.contains("PP/PPL restrictions still apply"));
    }
}
