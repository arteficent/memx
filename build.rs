fn main() {
    #[cfg(feature = "desktop-ui")]
    {
        let mut windows = tauri_build::WindowsAttributes::new().static_vc_runtime(true);
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            windows = windows.app_manifest(include_str!("memx.manifest"));
        }
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
            .expect("building Tauri resources");
    }
}