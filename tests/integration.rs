#![cfg(windows)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde_json::Value;

struct Fixture {
    child: Child,
    info: Value,
}

impl Fixture {
    fn start() -> Self {
        Self::start_at(env!("CARGO_BIN_EXE_memx-fixture"))
    }

    fn start_at(path: &str) -> Self {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn fixture");
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
        let info: Value = serde_json::from_str(&line).expect("fixture json");
        Self { child, info }
    }

    fn pid(&self) -> String {
        self.info["pid"].to_string()
    }

    fn addr(&self, key: &str) -> String {
        self.info[key].as_str().unwrap().to_string()
    }

    fn addr_u64(&self, key: &str) -> u64 {
        u64::from_str_radix(self.addr(key).trim_start_matches("0x"), 16).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let _ = stdin.write_all(b"\n");
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn memx(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_memx")).args(args).output().expect("run memx");
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn memx_json(args: &[&str]) -> Value {
    let mut a = args.to_vec();
    a.push("--json");
    let (ok, out, err) = memx(&a);
    assert!(ok, "memx {args:?} failed: {err}");
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("bad json from {args:?}: {e}\n{out}"))
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn ps_finds_fixture() {
    let f = Fixture::start();
    let v = memx_json(&["ps", "--filter", "memx-fixture*"]);
    let pid: u64 = f.pid().parse().unwrap();
    assert!(v.as_array().unwrap().iter().any(|p| p["pid"].as_u64() == Some(pid)));
}

#[test]
fn process_snapshot_dump_contains_fixture_and_refuses_overwrite() {
    let fixture = Fixture::start();
    let backend = memx::backend::native().unwrap();
    let process = backend.open(fixture.info["pid"].as_u64().unwrap() as u32, &memx::backend::OpenOptions::default()).unwrap();
    let path = std::env::temp_dir().join(format!("memx-fixture-{}-{}.dmp", std::process::id(), fixture.pid()));
    let report = process.dump(&path).unwrap();
    assert_eq!(report.mode, "pss_full_memory");
    assert!(report.capture_completed_unix_ms >= report.capture_started_unix_ms);
    assert!(report.finished_unix_ms >= report.capture_completed_unix_ms);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..4], b"MDMP");
    assert!(bytes.windows(b"fixture-global".len()).any(|window| window == b"fixture-global"));
    assert!(bytes.windows(b"fixture-heap".len()).any(|window| window == b"fixture-heap"));
    assert!(process.dump(&path).is_err());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), report.bytes);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn cli_and_desktop_capture_snapshot_dumps() {
    let fixture = Fixture::start();
    let path = std::env::temp_dir().join(format!("memx-cli-{}-{}.dmp", std::process::id(), fixture.pid()));
    let report = memx_json(&["dump", "--pid", &fixture.pid(), "--file", path.to_str().unwrap()]);
    assert_eq!(report["mode"], "pss_full_memory");
    std::fs::remove_file(&path).unwrap();
    let service = memx::desktop::DesktopService::start().unwrap();
    service.request(memx::desktop::Request::Attach { pid: fixture.info["pid"].as_u64().unwrap() as u32, symbols: false, symbol_path: None }).unwrap();
    let report = service.request(memx::desktop::Request::Dump { path: path.to_str().unwrap().to_string() }).unwrap();
    assert_eq!(report["mode"], "pss_full_memory");
    assert!(report["bytes"].as_u64().unwrap() > 0);
    std::fs::remove_file(path).unwrap();
}

#[cfg(feature = "desktop-ui")]
#[test]
fn unified_executable_runs_cli_without_opening_a_window() {
    let output = Command::new(env!("CARGO_BIN_EXE_memx-ui")).args(["ps", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let processes: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!processes.as_array().unwrap().is_empty());
}

#[test]
fn regions_are_labeled() {
    let f = Fixture::start();
    let pid = f.pid();
    let regions = memx_json(&["regions", "--pid", &pid]);
    let regions = regions.as_array().unwrap();
    let containing = |a: u64| {
        regions
            .iter()
            .find(|r| {
                let base = hex(&r["base"]);
                a >= base && a < base + r["size"].as_u64().unwrap()
            })
            .unwrap_or_else(|| panic!("no region for 0x{a:x}"))
    };
    let heap = containing(f.addr_u64("heap"));
    assert_eq!(heap["state"], "commit");
    assert!(heap["label"].as_str().unwrap_or("").contains("heap"), "{heap}");
    let global = containing(f.addr_u64("global"));
    assert_eq!(global["kind"], "image");
    assert!(global["label"].as_str().unwrap().contains("memx-fixture.exe .data"), "{global}");
    assert!(regions.iter().any(|r| r["label"].as_str().is_some_and(|l| l.starts_with("stack T"))));
    assert!(regions.iter().any(|r| r["label"].as_str().is_some_and(|l| l.contains("PEB"))));
}

#[test]
fn modules_and_threads() {
    let f = Fixture::start();
    let pid = f.pid();
    let mods = memx_json(&["modules", "--pid", &pid]);
    let names: Vec<String> = mods.as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_lowercase()).collect();
    assert!(names.contains(&"memx-fixture.exe".to_string()));
    assert!(names.contains(&"ntdll.dll".to_string()));
    let threads = memx_json(&["threads", "--pid", &pid]);
    assert!(threads.as_array().unwrap().iter().any(|t| !t["stacks"].as_array().unwrap().is_empty()));
}

#[test]
fn read_typed_values() {
    let f = Fixture::start();
    let pid = f.pid();
    let read = |key: &str, ty: &str| memx_json(&["read", "--pid", &pid, "--addr", &f.addr(key), "--as", ty])[0]["value"].clone();
    assert_eq!(read("magic", "u64"), "3735928559");
    assert_eq!(read("count", "i64"), "-42");
    assert_eq!(read("pi", "f64"), "3.14159");
    assert_eq!(read("name", "cstr"), "\"fixture-global\"");
    assert_eq!(read("wname", "wstr"), "\"wide-global\"");
    let ratios = memx_json(&["read", "--pid", &pid, "--addr", &f.addr("ratios"), "--as", "f32[2]"]);
    assert_eq!(ratios[0]["value"], "1.25");
    assert_eq!(ratios[1]["value"], "0.5");
}

#[test]
fn hexdump_and_partial_reads() {
    let f = Fixture::start();
    let pid = f.pid();
    let (ok, out, err) = memx(&["read", "--pid", &pid, "--addr", &f.addr("magic"), "--len", "4"]);
    assert!(ok, "{err}");
    assert!(out.contains("ef be ad de"), "{out}");
    // Read ending past the last committed page of the heap region must succeed with ?? markers.
    let regions = memx_json(&["regions", "--pid", &pid, "--committed"]);
    let heap = f.addr_u64("heap");
    let r = regions
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            let b = hex(&r["base"]);
            heap >= b && heap < b + r["size"].as_u64().unwrap()
        })
        .unwrap();
    let end = hex(&r["base"]) + r["size"].as_u64().unwrap();
    let start = format!("0x{:x}", end - 8);
    let dump = memx_json(&["read", "--pid", &pid, "--addr", &start, "--len", "16"]);
    let h = dump["hex"].as_str().unwrap();
    assert_eq!(h.len(), 32);
    assert!(h.ends_with("????????????????"), "{h}");
}

#[test]
fn inspect_heuristics_on_heap_object() {
    let f = Fixture::start();
    let pid = f.pid();
    let anns = memx_json(&["inspect", "--pid", &pid, "--addr", &f.addr("heap"), "--len", "88", "--no-symbols"]);
    let anns = anns.as_array().unwrap();
    let at = |a: u64| anns.iter().find(|x| hex(&x["addr"]) == a).unwrap_or_else(|| panic!("no annotation at 0x{a:x}: {anns:?}"));
    let base = f.addr_u64("heap");
    if cfg!(target_pointer_width = "64") {
        assert_eq!(at(base)["type"], "int");
        assert_eq!(at(base + 16)["type"], "f64");
        assert_eq!(at(base + 16)["value"], "2.71828");
        assert_eq!(at(base + 24)["type"], "f32 x2");
        assert_eq!(at(base + 24)["value"], "0.75, 4");
    }
    assert_eq!(at(base + 8)["value"], "7 (0x7)");
    assert_eq!(at(base + 32)["type"], "cstr");
    assert_eq!(at(base + 32)["value"], "\"fixture-heap\"");
    assert_eq!(at(base + 48)["type"], "wstr");
    assert_eq!(at(base + 48)["value"], "\"wide-heap\"");
    let next = at(f.addr_u64("heap_next"));
    assert_eq!(next["type"], "ptr");
    assert!(next["value"].as_str().unwrap().contains("memx-fixture.exe"), "{next}");
}

#[test]
fn symbols_resolve_and_type_globals() {
    let f = Fixture::start();
    let pid = f.pid();
    let s = memx_json(&["symbol", "--pid", &pid, "memx-fixture!FIXTURE_GLOBAL"]);
    assert_eq!(hex(&s["address"]), f.addr_u64("global"), "{s}");
    let anns = memx_json(&["inspect", "--pid", &pid, "--addr", "memx-fixture!FIXTURE_GLOBAL", "--len", "88"]);
    let anns = anns.as_array().unwrap();
    let field = |name: &str| {
        anns.iter()
            .find(|a| a["field"].as_str().is_some_and(|f| f.ends_with(name)))
            .unwrap_or_else(|| panic!("no field {name}: {anns:?}"))
    };
    assert_eq!(field(".pi")["value"], "3.14159");
    assert_eq!(field(".pi")["source"], "symbol");
    assert_eq!(field(".count")["value"], "-42");
    assert_eq!(field(".name")["value"], "\"fixture-global\"");
    assert!(field(".next")["value"].as_str().unwrap().contains("heap"), "{:?}", field(".next"));
}

#[test]
fn search_finds_strings_and_values() {
    let f = Fixture::start();
    let pid = f.pid();
    let hits = memx_json(&["search", "--pid", &pid, "--string", "fixture-heap"]);
    let name = f.addr_u64("heap_name");
    assert!(hits.as_array().unwrap().iter().any(|h| hex(&h["address"]) == name), "{hits}");
    let hits = memx_json(&["search", "--pid", &pid, "--f64", "3.14159", "--aligned"]);
    let pi = f.addr_u64("pi");
    assert!(hits.as_array().unwrap().iter().any(|h| hex(&h["address"]) == pi), "{hits}");
}

#[test]
fn suspend_resumes_target() {
    let mut f = Fixture::start();
    let pid = f.pid();
    let v = memx_json(&["read", "--pid", &pid, "--addr", &f.addr("pi"), "--as", "f64", "--suspend"]);
    assert_eq!(v[0]["value"], "3.14159");
    // A resumed fixture exits promptly once stdin gets a line.
    f.child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    let status = f.child.wait().unwrap();
    assert!(status.success());
}

#[cfg(target_pointer_width = "32")]
#[test]
fn x86_build_refuses_64_bit_targets_with_guidance() {
    let catalog = memx::backend::native().unwrap().list_catalog().unwrap();
    let target = catalog.iter().find(|process| process.access == "x64_required")
        .expect("a 64-bit process should be running on a 64-bit Windows host");
    let (ok, _, err) = memx(&["regions", "--pid", &target.info.pid.to_string()]);
    assert!(!ok);
    assert!(err.contains("x64 memx build"), "{err}");
}

#[test]
fn errors_are_clean() {
    let (ok, _, err) = memx(&["regions", "--pid", "4294967290"]);
    assert!(!ok);
    assert!(err.contains("no running process"), "{err}");
    let (ok, _, err) = memx(&["regions", "--name", "definitely-not-running-xyz"]);
    assert!(!ok);
    assert!(err.contains("no running process matches"), "{err}");
    // The System process can't be opened for memory reads without elevation.
    let (_, _, err) = memx(&["regions", "--pid", "4"]);
    assert!(!err.contains("panicked"), "{err}");
}

#[test]
fn desktop_browses_fixture_and_preserves_access_boundaries() {
    use memx::desktop::{DesktopService, Request};

    let fixture = Fixture::start();
    let service = DesktopService::start().unwrap();
    let request = |value: Value| service.request(serde_json::from_value::<Request>(value).unwrap());
    let processes = request(serde_json::json!({ "op": "processes" })).unwrap();
    let process = processes.as_array().unwrap().iter()
        .find(|process| process["pid"].as_u64() == fixture.info["pid"].as_u64()).unwrap();
    assert_eq!(process["access"], "readable");
    assert_eq!(process["pointer_size"], std::mem::size_of::<usize>());
    assert!(process["owner"].is_string());
    assert!(processes.as_array().unwrap().iter().any(|process| process["pid"] == 4));
    for service in processes.as_array().unwrap().iter().filter(|process| process["session_id"] == 0) {
        assert_eq!(service["category"], "system", "{service}");
    }
    let snapshot = request(serde_json::json!({ "op": "attach", "pid": fixture.info["pid"], "symbols": false })).unwrap();
    assert!(snapshot["readable_count"].as_u64().unwrap() > 0);
    let regions = request(serde_json::json!({ "op": "regions", "offset": 0, "limit": 2, "readable": true, "filter": "" })).unwrap();
    assert_eq!(regions["regions"].as_array().unwrap().len(), 2);
    assert!(regions["regions"][0]["base"].is_string());
    let values = request(serde_json::json!({ "op": "read", "address": fixture.addr("pi"), "len": 8, "data_type": "f64" })).unwrap();
    assert_eq!(values["values"][0]["value"], "3.14159");
    assert_eq!(values["values"][0]["source"], "user");
    let unreadable = request(serde_json::json!({ "op": "read", "address": "0x0", "len": 8, "data_type": "u64" })).unwrap();
    assert_eq!(unreadable["valid_count"], 0);
    assert_eq!(unreadable["values"][0]["value"], "??");
    assert!(request(serde_json::json!({ "op": "read", "address": "0x0", "len": 4097, "data_type": "hex" })).is_err());
    request(serde_json::json!({ "op": "refresh" })).unwrap();
    request(serde_json::json!({ "op": "detach" })).unwrap();
    assert!(request(serde_json::json!({ "op": "modules" })).is_err());
    request(serde_json::json!({ "op": "attach", "pid": fixture.info["pid"], "symbols": true })).unwrap();
    let symbols = request(serde_json::json!({ "op": "read", "address": "memx-fixture!FIXTURE_GLOBAL", "len": 88, "data_type": "auto" })).unwrap();
    assert!(symbols["values"].as_array().unwrap().iter().any(|value| value["source"] == "symbol" && value["value"] == "3.14159"));
    request(serde_json::json!({ "op": "refresh" })).unwrap();
    let refreshed = request(serde_json::json!({ "op": "read", "address": "memx-fixture!FIXTURE_GLOBAL", "len": 88, "data_type": "auto" })).unwrap();
    assert!(refreshed["values"].as_array().unwrap().iter().any(|value| value["source"] == "symbol" && value["value"] == "3.14159"));
}

#[test]
fn desktop_reads_wow64_fixture_when_provided() {
    use memx::desktop::{DesktopService, Request};

    let Some(path) = std::env::var_os("MEMX_X86_FIXTURE") else { return };
    let fixture = Fixture::start_at(path.to_str().unwrap());
    let service = DesktopService::start().unwrap();
    let request = |value: Value| service.request(serde_json::from_value::<Request>(value).unwrap());
    let processes = request(serde_json::json!({ "op": "processes" })).unwrap();
    let process = processes.as_array().unwrap().iter()
        .find(|process| process["pid"].as_u64() == fixture.info["pid"].as_u64()).unwrap();
    assert_eq!(process["pointer_size"], 4);
    let snapshot = request(serde_json::json!({ "op": "attach", "pid": fixture.info["pid"], "symbols": false })).unwrap();
    assert_eq!(snapshot["info"]["pointer_size"], 4);
    let value = request(serde_json::json!({ "op": "read", "address": fixture.addr("pi"), "len": 8, "data_type": "f64" })).unwrap();
    assert_eq!(value["values"][0]["value"], "3.14159");
    let pointer = request(serde_json::json!({ "op": "read", "address": fixture.addr("heap_next"), "len": 4, "data_type": "auto" })).unwrap();
    assert_eq!(pointer["values"][0]["len"], 4);
    assert!(pointer["values"][0]["value"].as_str().unwrap().contains("memx-fixture.exe"));
    let path = std::env::temp_dir().join(format!("memx-wow64-{}-{}.dmp", std::process::id(), fixture.pid()));
    let dump = request(serde_json::json!({ "op": "dump", "path": path.to_str().unwrap() })).unwrap();
    assert_eq!(dump["mode"], "pss_full_memory");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..4], b"MDMP");
    assert!(bytes.windows(b"fixture-heap".len()).any(|window| window == b"fixture-heap"));
    std::fs::remove_file(path).unwrap();
}
