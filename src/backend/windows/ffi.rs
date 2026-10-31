//! Undocumented-but-stable ntdll entry points and structures.
#![allow(non_snake_case)]

use std::ffi::c_void;

use windows_sys::Win32::Foundation::HANDLE;

pub const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
pub const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;
pub const THREAD_BASIC_INFORMATION_CLASS: u32 = 0;

#[repr(C)]
#[derive(Default)]
pub struct ProcessBasicInformation {
    pub exit_status: i32,
    pub peb: usize,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_pid: usize,
    pub inherited_pid: usize,
}

#[repr(C)]
#[derive(Default)]
pub struct ThreadBasicInformation {
    pub exit_status: i32,
    pub teb: usize,
    pub client_pid: usize,
    pub client_tid: usize,
    pub affinity_mask: usize,
    pub priority: i32,
    pub base_priority: i32,
}

#[cfg_attr(target_arch = "x86", link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated"))]
#[cfg_attr(not(target_arch = "x86"), link(name = "ntdll", kind = "raw-dylib"))]
extern "system" {
    pub fn NtQueryInformationProcess(h: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    pub fn NtQueryInformationThread(h: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    pub fn NtSuspendProcess(h: HANDLE) -> i32;
    pub fn NtResumeProcess(h: HANDLE) -> i32;
}
