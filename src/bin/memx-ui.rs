#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use memx::desktop::{DesktopService, Request};
use memx::startup::{self, StartupStatus};
use serde_json::Value;
use tauri::State;

#[tauri::command]
async fn memory_request(service: State<'_, DesktopService>, request: Request) -> Result<Value, String> {
    let service = service.inner().clone();
    tauri::async_runtime::spawn_blocking(move || service.request(request)).await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
fn startup_status() -> Result<StartupStatus, String> {
    startup::status().map_err(|error| format!("{error:#}"))
}

#[tauri::command]
fn startup_set(enabled: bool) -> Result<StartupStatus, String> {
    let result = if enabled {
        std::env::current_exe().map_err(anyhow::Error::from).and_then(|path| startup::enable(&path))
    } else { startup::disable() };
    result.map_err(|error| format!("{error:#}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() > 1 {
        #[cfg(windows)]
        unsafe { windows_sys::Win32::System::Console::AttachConsole(u32::MAX) };
        let code = memx::cli::entry();
        if code == std::process::ExitCode::SUCCESS { return Ok(()); }
        std::process::exit(1);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DesktopService::start()?)
        .invoke_handler(tauri::generate_handler![memory_request, startup_status, startup_set])
        .run(tauri::generate_context!())?;
    Ok(())
}