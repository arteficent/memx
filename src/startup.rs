use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct StartupStatus {
    pub enabled: bool,
    pub command: Option<String>,
    pub mode: &'static str,
    pub launch_elevated: bool,
    pub legacy_enabled: bool,
}

pub fn is_elevated() -> bool {
    #[cfg(windows)]
    { crate::backend::windows::current_process_is_elevated().unwrap_or(false) }
    #[cfg(not(windows))]
    { false }
}

fn startup_command(executable: &Path) -> Result<String> {
    let executable = executable.canonicalize().context("startup executable must exist")?;
    if !executable.is_file() || !executable.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("exe")) {
        bail!("startup target must be an existing Windows .exe file");
    }
    let executable = executable.to_str().context("startup path is not valid Unicode")?;
    if executable.contains(['"', '\0', '\r', '\n']) {
        bail!("invalid startup executable path");
    }
    let executable = executable.strip_prefix("\\\\?\\").unwrap_or(executable);
    Ok(format!("\"{executable}\""))
}

pub fn status() -> Result<StartupStatus> {
    #[cfg(windows)]
    { tasks::status() }
    #[cfg(not(windows))]
    { bail!("startup registration is supported on Windows only") }
}

pub fn enable(executable: &Path) -> Result<StartupStatus> {
    let command = startup_command(executable)?;
    #[cfg(windows)]
    { tasks::enable(executable, &command) }
    #[cfg(not(windows))]
    { let _ = command; bail!("startup registration is supported on Windows only") }
}

pub fn disable() -> Result<StartupStatus> {
    #[cfg(windows)]
    { tasks::disable() }
    #[cfg(not(windows))]
    { bail!("startup registration is supported on Windows only") }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ};

    const KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const VALUE: &str = "memx.inspector";

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) { unsafe { RegCloseKey(self.0) }; }
    }

    fn wide(value: &str) -> Vec<u16> { value.encode_utf16().chain(Some(0)).collect() }

    fn check(result: u32, api: &str) -> Result<()> {
        if result != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(result as i32)).with_context(|| api.to_owned());
        }
        Ok(())
    }

    pub fn status() -> Result<StartupStatus> {
        let mut key = std::ptr::null_mut();
        let opened = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide(KEY).as_ptr(), 0, KEY_QUERY_VALUE, &mut key) };
        let mut status = StartupStatus { enabled: false, command: None, mode: "legacy_user_sign_in", launch_elevated: false, legacy_enabled: false };
        if opened == ERROR_FILE_NOT_FOUND { return Ok(status); }
        check(opened, "RegOpenKeyExW")?;
        let key = Key(key);
        let name = wide(VALUE);
        let (mut kind, mut bytes) = (0, 0);
        let queried = unsafe { RegQueryValueExW(key.0, name.as_ptr(), std::ptr::null(), &mut kind, std::ptr::null_mut(), &mut bytes) };
        if queried == ERROR_FILE_NOT_FOUND { return Ok(status); }
        check(queried, "RegQueryValueExW")?;
        if kind != REG_SZ || bytes > 65536 || bytes % 2 != 0 { bail!("invalid memx startup registry value"); }
        let mut buffer = vec![0u16; bytes as usize / 2];
        check(unsafe { RegQueryValueExW(key.0, name.as_ptr(), std::ptr::null(), &mut kind, buffer.as_mut_ptr().cast(), &mut bytes) }, "RegQueryValueExW")?;
        let len = buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len());
        let command = String::from_utf16(&buffer[..len]).context("startup value is not valid UTF-16")?;
        status.enabled = !command.is_empty();
        status.command = Some(command);
        Ok(status)
    }

    pub fn set(command: Option<&str>) -> Result<StartupStatus> {
        let mut key = std::ptr::null_mut();
        check(unsafe { RegCreateKeyExW(HKEY_CURRENT_USER, wide(KEY).as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, std::ptr::null(), &mut key, std::ptr::null_mut()) }, "RegCreateKeyExW")?;
        let key = Key(key);
        let name = wide(VALUE);
        let result = match command {
            Some(command) => {
                let bytes: Vec<u8> = wide(command).iter().flat_map(|unit| unit.to_le_bytes()).collect();
                unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_SZ, bytes.as_ptr(), bytes.len() as u32) }
            }
            None => unsafe { RegDeleteValueW(key.0, name.as_ptr()) },
        };
        if result != ERROR_FILE_NOT_FOUND || command.is_some() { check(result, "updating memx startup entry")?; }
        status()
    }
}

#[cfg(windows)]
mod tasks {
    use super::*;
    use std::path::PathBuf;
    use ::windows::core::{Interface, BSTR};
    use ::windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
    use ::windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
    use ::windows::Win32::System::TaskScheduler::{IExecAction, ILogonTrigger, ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE, TASK_INSTANCES_IGNORE_NEW, TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_LOGON};
    use ::windows::Win32::System::Variant::VARIANT;
    use ::windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT};
    use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct Apartment(bool);
    impl Drop for Apartment {
        fn drop(&mut self) { if self.0 { unsafe { CoUninitialize() }; } }
    }

    struct Scheduler {
        folder: ITaskFolder,
        service: ITaskService,
        _apartment: Apartment,
        sid: String,
        name: BSTR,
    }

    fn current_sid() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error()).context("reading current user token");
        }
        let token = crate::backend::windows::OwnedHandle(token);
        let mut needed = 0;
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 { bail!("cannot query current user SID"); }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe { GetTokenInformation(token.0, TokenUser, buffer.as_mut_ptr().cast(), needed, &mut needed) } == 0 {
            return Err(std::io::Error::last_os_error()).context("reading current user SID");
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
            return Err(std::io::Error::last_os_error()).context("formatting current user SID");
        }
        let len = (0..256).take_while(|offset| unsafe { *sid.add(*offset) } != 0).count();
        let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid, len) });
        unsafe { LocalFree(sid.cast()) };
        Ok(name)
    }

    fn missing(error: &::windows::core::Error) -> bool {
        matches!(error.code().0 as u32, 0x8007_0002 | 0x8004_130F)
    }

    impl Scheduler {
        fn connect() -> Result<Self> {
            let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if initialized.is_err() && initialized.0 as u32 != 0x8001_0106 { initialized.ok()?; }
            let apartment = Apartment(initialized.is_ok());
            let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }?;
            let empty = VARIANT::default();
            unsafe { service.Connect(&empty, &empty, &empty, &empty) }?;
            let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }?;
            let sid = current_sid()?;
            let name = BSTR::from(format!("memx.Inspector.{sid}"));
            Ok(Self { folder, service, _apartment: apartment, sid, name })
        }
    }

    fn require_admin() -> Result<()> {
        if !is_elevated() { bail!("startup changes require an elevated memx instance; start it yourself with administrator privileges"); }
        Ok(())
    }

    fn require_installed_path(executable: &Path) -> Result<()> {
        let executable = executable.canonicalize()?;
        let program_files = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }?;
        let directory = unsafe { program_files.to_string() };
        unsafe { CoTaskMemFree(Some(program_files.0.cast())) };
        let root = PathBuf::from(directory?).canonicalize()?;
        if !executable.starts_with(&root) {
            bail!("elevated startup requires the per-machine installation under Program Files; install memx before enabling startup");
        }
        Ok(())
    }

    pub fn status() -> Result<StartupStatus> {
        let scheduler = Scheduler::connect()?;
        let legacy_enabled = super::windows::status()?.enabled;
        let task = match unsafe { scheduler.folder.GetTask(&scheduler.name) } {
            Ok(task) => task,
            Err(error) if missing(&error) => return Ok(StartupStatus { enabled: legacy_enabled, command: None, mode: "elevated_user_sign_in", launch_elevated: false, legacy_enabled }),
            Err(error) => return Err(error.into()),
        };
        let definition = unsafe { task.Definition() }?;
        let principal = unsafe { definition.Principal() }?;
        let mut run_level = TASK_RUNLEVEL_HIGHEST;
        let mut user_id = BSTR::new();
        unsafe { principal.RunLevel(&mut run_level)?; principal.UserId(&mut user_id)?; }
        let elevated = run_level == TASK_RUNLEVEL_HIGHEST && user_id == scheduler.sid;
        let action: IExecAction = unsafe { definition.Actions()?.get_Item(1) }?.cast()?;
        let mut command = BSTR::new();
        unsafe { action.Path(&mut command) }?;
        Ok(StartupStatus {
            enabled: unsafe { task.Enabled() }?.0 != 0 || legacy_enabled,
            command: Some(command.to_string()),
            mode: "elevated_user_sign_in", launch_elevated: elevated, legacy_enabled,
        })
    }

    pub fn enable(executable: &Path, _command: &str) -> Result<StartupStatus> {
        require_admin()?;
        require_installed_path(executable)?;
        let scheduler = Scheduler::connect()?;
        let definition = unsafe { scheduler.service.NewTask(0) }?;
        unsafe {
            definition.RegistrationInfo()?.SetDescription(&BSTR::from("memx administrator process inspector at current-user sign-in"))?;
            let principal = definition.Principal()?;
            principal.SetUserId(&BSTR::from(&scheduler.sid))?;
            principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
            principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;
            let settings = definition.Settings()?;
            settings.SetStartWhenAvailable(VARIANT_TRUE)?;
            settings.SetDisallowStartIfOnBatteries(VARIANT_FALSE)?;
            settings.SetStopIfGoingOnBatteries(VARIANT_FALSE)?;
            settings.SetExecutionTimeLimit(&BSTR::from("PT0S"))?;
            settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)?;
            let trigger: ILogonTrigger = definition.Triggers()?.Create(TASK_TRIGGER_LOGON)?.cast()?;
            trigger.SetUserId(&BSTR::from(&scheduler.sid))?;
            trigger.SetEnabled(VARIANT_TRUE)?;
            let action: IExecAction = definition.Actions()?.Create(TASK_ACTION_EXEC)?.cast()?;
            let command = startup_command(executable)?;
            action.SetPath(&BSTR::from(command.trim_matches('"')))?;
            scheduler.folder.RegisterTaskDefinition(&scheduler.name, &definition, TASK_CREATE_OR_UPDATE.0,
                &VARIANT::from(BSTR::from(&scheduler.sid)), &VARIANT::default(), TASK_LOGON_INTERACTIVE_TOKEN, &VARIANT::default())?;
        }
        super::windows::set(None)?;
        status()
    }

    pub fn disable() -> Result<StartupStatus> {
        require_admin()?;
        let scheduler = Scheduler::connect()?;
        match unsafe { scheduler.folder.DeleteTask(&scheduler.name, 0) } {
            Ok(()) => {}
            Err(error) if missing(&error) => {}
            Err(error) => return Err(error.into()),
        }
        super::windows::set(None)?;
        status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_requires_an_existing_executable() {
        assert!(startup_command(Path::new("missing-memx-startup.exe")).is_err());
        assert!(startup_command(Path::new("Cargo.toml")).is_err());
        let command = startup_command(&std::env::current_exe().unwrap()).unwrap();
        assert!(command.starts_with('"') && command.ends_with('"'));
    }

    #[test]
    fn startup_cannot_register_a_development_executable() {
        assert!(enable(&std::env::current_exe().unwrap()).is_err());
    }
}