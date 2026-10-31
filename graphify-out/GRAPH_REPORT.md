# Graph Report - .  (2026-10-31)

## Corpus Check
- Corpus is ~33,373 words - fits in a single context window. You may not need a graph.

## Summary
- 748 nodes · 1526 edges · 39 communities (37 shown, 2 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 76 edges (avg confidence: 0.86)
- Token cost: 30,000 input · 14,000 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Windows Process Backend|Windows Process Backend]]
- [[_COMMUNITY_Memory Data Model|Memory Data Model]]
- [[_COMMUNITY_Session And Target Resolution|Session And Target Resolution]]
- [[_COMMUNITY_DbgHelp Symbol Provider|DbgHelp Symbol Provider]]
- [[_COMMUNITY_Type Inference Engine|Type Inference Engine]]
- [[_COMMUNITY_CLI Command Dispatch|CLI Command Dispatch]]
- [[_COMMUNITY_Elevated Startup Scheduling|Elevated Startup Scheduling]]
- [[_COMMUNITY_Integration Test Suite|Integration Test Suite]]
- [[_COMMUNITY_Terminal UI|Terminal UI]]
- [[_COMMUNITY_Exact Type Decoding|Exact Type Decoding]]
- [[_COMMUNITY_Tauri App Configuration|Tauri App Configuration]]
- [[_COMMUNITY_Frontend Package Manifest|Frontend Package Manifest]]
- [[_COMMUNITY_Snapshot Dump Writer|Snapshot Dump Writer]]
- [[_COMMUNITY_Desktop UI Script|Desktop UI Script]]
- [[_COMMUNITY_Desktop Request Worker|Desktop Request Worker]]
- [[_COMMUNITY_Paged Memory Reader|Paged Memory Reader]]
- [[_COMMUNITY_CLI Definitions|CLI Definitions]]
- [[_COMMUNITY_Core Architecture Components|Core Architecture Components]]
- [[_COMMUNITY_Tauri Entry Commands|Tauri Entry Commands]]
- [[_COMMUNITY_Region Labeling|Region Labeling]]
- [[_COMMUNITY_PE Header Parsing|PE Header Parsing]]
- [[_COMMUNITY_Region Map Lookup|Region Map Lookup]]
- [[_COMMUNITY_Backend Trait Abstraction|Backend Trait Abstraction]]
- [[_COMMUNITY_Product Docs And Website|Product Docs And Website]]
- [[_COMMUNITY_Bitness And Test Coverage|Bitness And Test Coverage]]
- [[_COMMUNITY_Memory Search|Memory Search]]
- [[_COMMUNITY_Typing And Symbol Design|Typing And Symbol Design]]
- [[_COMMUNITY_MSVC RTTI Decoding|MSVC RTTI Decoding]]
- [[_COMMUNITY_Front-end And IPC Design|Front-end And IPC Design]]
- [[_COMMUNITY_Privilege And Deployment Plan|Privilege And Deployment Plan]]
- [[_COMMUNITY_Versioning And CI Workflows|Versioning And CI Workflows]]
- [[_COMMUNITY_Version Script|Version Script]]
- [[_COMMUNITY_Tauri Capabilities|Tauri Capabilities]]
- [[_COMMUNITY_Access Boundaries|Access Boundaries]]
- [[_COMMUNITY_Known-Value Fixture|Known-Value Fixture]]
- [[_COMMUNITY_CLI Entry Point|CLI Entry Point]]
- [[_COMMUNITY_NT Native Structures|NT Native Structures]]

## God Nodes (most connected - your core abstractions)
1. `Session` - 34 edges
2. `DbgHelp` - 23 edges
3. `WinProcess` - 22 edges
4. `App` - 21 edges
5. `Protect` - 17 edges
6. `annotate()` - 16 edges
7. `Result` - 15 edges
8. `memx (read-only Windows process memory inspector)` - 14 edges
9. `decode()` - 13 edges
10. `memx_json()` - 13 edges

## Surprising Connections (you probably didn't know these)
- `Backend abstraction (ProcessBackend / Process traits)` --references--> `Process`  [EXTRACTED]
  docs/ARCHITECTURE.md → src/backend/mod.rs
- `Test WOW64 inspection from the x64 build` --references--> `desktop_reads_wow64_fixture_when_provided()`  [EXTRACTED]
  .github/workflows/pull-request.yml → tests/integration.rs
- `Website access limits section` --semantically_similar_to--> `Access and safety principles`  [INFERRED] [semantically similar]
  docs/index.html → README.md
- `Backend abstraction (ProcessBackend / Process traits)` --references--> `ProcessBackend`  [EXTRACTED]
  docs/ARCHITECTURE.md → src/backend/mod.rs
- `Website build from source section` --conceptually_related_to--> `Pull request workflow`  [INFERRED]
  docs/index.html → .github/workflows/pull-request.yml

## Import Cycles
- 1-file cycle: `src/backend/mod.rs -> src/backend/mod.rs`
- 1-file cycle: `src/backend/windows/dump.rs -> src/backend/windows/dump.rs`
- 1-file cycle: `src/backend/windows/mod.rs -> src/backend/windows/mod.rs`
- 1-file cycle: `src/backend/windows/symbols.rs -> src/backend/windows/symbols.rs`
- 1-file cycle: `src/bin/memx-ui.rs -> src/bin/memx-ui.rs`
- 1-file cycle: `src/cli.rs -> src/cli.rs`
- 1-file cycle: `src/commands.rs -> src/commands.rs`
- 1-file cycle: `src/decode.rs -> src/decode.rs`
- 1-file cycle: `src/desktop.rs -> src/desktop.rs`
- 1-file cycle: `src/format.rs -> src/format.rs`
- 1-file cycle: `src/infer.rs -> src/infer.rs`
- 1-file cycle: `src/labels.rs -> src/labels.rs`
- 1-file cycle: `src/startup.rs -> src/startup.rs`
- 1-file cycle: `src/pe.rs -> src/pe.rs`
- 1-file cycle: `src/reader.rs -> src/reader.rs`
- 1-file cycle: `src/rtti.rs -> src/rtti.rs`
- 1-file cycle: `src/search.rs -> src/search.rs`
- 1-file cycle: `src/session.rs -> src/session.rs`
- 1-file cycle: `src/tui.rs -> src/tui.rs`
- 1-file cycle: `tests/integration.rs -> tests/integration.rs`

## Hyperedges (group relationships)
- **CLI, TUI and Tauri GUI in one executable sharing the Rust core and Session** — docs_architecture_cli, docs_architecture_tui, docs_architecture_tauri_desktop, docs_architecture_shared_session, readme_memx_ui_exe [EXTRACTED 1.00]
- **MVP = Phases 0-3 (list regions and view raw content)** — docs_plan_phase_0_setup, docs_plan_phase_1_process_open, docs_plan_phase_2_regions, docs_plan_phase_3_read_hexdump [EXTRACTED 1.00]
- **Type provenance: Symbol, RTTI, Heuristic and User sources** — docs_architecture_symbol_resolver, docs_architecture_msvc_rtti, docs_architecture_type_inference_engine, docs_architecture_type_decoder, readme_type_sources [INFERRED 0.85]

## Communities (39 total, 2 thin omitted)

### Community 0 - "Windows Process Backend"
Cohesion: 0.07
Nodes (47): FnOnce, MutexGuard, OpenOptions, ProcessSummary, Box, c_void, Drop, DumpReport (+39 more)

### Community 1 - "Memory Data Model"
Cohesion: 0.09
Nodes (28): Display, Formatter, Ok, S, DumpReport, Field, MemKind, MemState (+20 more)

### Community 2 - "Session And Target Resolution"
Cohesion: 0.08
Nodes (26): PageCache, glob_match(), name_matches(), parse_number(), resolve_target(), Box, Drop, InferCtx (+18 more)

### Community 3 - "DbgHelp Symbol Provider"
Cohesion: 0.11
Nodes (27): DataType, Field, IMAGEHLP_SYMBOL_TYPE_INFO, OwnedHandle, RefCell, Box, c_void, Drop (+19 more)

### Community 4 - "Type Inference Engine"
Cohesion: 0.15
Nodes (33): Into, annotate(), annotate_symbol(), Annotation, classifies_common_slots(), Confidence, detect_string(), flatten() (+25 more)

### Community 5 - "CLI Command Dispatch"
Cohesion: 0.13
Nodes (30): Annotation, Cli, Serialize, Ctx, describe_region(), header(), ProcessBackend, Result (+22 more)

### Community 6 - "Elevated Startup Scheduling"
Cohesion: 0.15
Nodes (28): BSTR, ITaskFolder, ITaskService, Apartment, check(), current_sid(), disable(), enable() (+20 more)

### Community 7 - "Integration Test Suite"
Cohesion: 0.18
Nodes (24): Child, cli_and_desktop_capture_snapshot_dumps(), desktop_browses_fixture_and_preserves_access_boundaries(), desktop_reads_wow64_fixture_when_provided(), errors_are_clean(), Fixture, hex(), hexdump_and_partial_reads() (+16 more)

### Community 8 - "Terminal UI"
Cohesion: 0.14
Nodes (16): DefaultTerminal, Frame, KeyCode, KeyEvent, Line, ListState, App, Focus (+8 more)

### Community 9 - "Exact Type Decoding"
Cohesion: 0.14
Nodes (20): FromStr, civil_from_days(), DataType, decode(), decode_spec(), decode_string(), fmt_f32(), fmt_f64() (+12 more)

### Community 10 - "Tauri App Configuration"
Cohesion: 0.08
Nodes (24): app, security, windows, build, beforeBuildCommand, beforeDevCommand, devUrl, features (+16 more)

### Community 11 - "Frontend Package Manifest"
Cohesion: 0.08
Nodes (23): dependencies, @fontsource/ibm-plex-mono, @fontsource/ibm-plex-sans, lucide, @tauri-apps/api, @tauri-apps/plugin-dialog, devDependencies, @tauri-apps/cli (+15 more)

### Community 12 - "Snapshot Dump Writer"
Cohesion: 0.14
Nodes (18): File, MINIDUMP_CALLBACK_INPUT, MINIDUMP_CALLBACK_OUTPUT, c_void, Drop, DumpReport, HANDLE, Option (+10 more)

### Community 13 - "Desktop UI Script"
Cohesion: 0.26
Nodes (19): address(), attach(), byId(), clearMemory(), controls(), escape(), icons(), iconSet (+11 more)

### Community 14 - "Desktop Request Worker"
Cohesion: 0.16
Nodes (14): Job, Reply, DesktopService, dispatch(), Request, Option, ProcessBackend, Result (+6 more)

### Community 15 - "Paged Memory Reader"
Cohesion: 0.18
Nodes (9): PageCache, ReadResult, HashMap, Option, Process, RegionMap, Self, Vec (+1 more)

### Community 16 - "CLI Definitions"
Cohesion: 0.20
Nodes (14): Command, Cli, Command, entry(), execute(), Pattern, ExitCode, Option (+6 more)

### Community 17 - "Core Architecture Components"
Cohesion: 0.21
Nodes (15): CLI front-end (clap), Formatters (table, hexdump, annotated, JSON), Paged Memory Reader + Cache, Process Resolver, Point-in-time process dumps (PSS VA clone + MiniDumpWriteDump), Region Labeler, Region Map Builder (RegionMap), Windows backend (Toolhelp32, VirtualQueryEx, ReadProcessMemory, PSAPI, DbgHelp) (+7 more)

### Community 18 - "Tauri Entry Commands"
Cohesion: 0.23
Nodes (13): main(), memory_request(), startup_set(), startup_status(), DesktopService, Request, Box, Error (+5 more)

### Community 19 - "Region Labeling"
Cohesion: 0.27
Nodes (13): Fn, apply(), basename(), index_of(), labels_modules_stacks_heaps(), modules_from_regions(), Module, Option (+5 more)

### Community 20 - "PE Header Parsing"
Cohesion: 0.31
Nodes (12): FnMut, Section, fake_image(), headers_and_exports(), parse_exports(), parse_headers(), PeHeaders, Option (+4 more)

### Community 21 - "Region Map Lookup"
Cohesion: 0.24
Nodes (7): lookup(), region(), RegionMap, Option, Region, Self, Vec

### Community 22 - "Backend Trait Abstraction"
Cohesion: 0.21
Nodes (11): native(), OpenOptions, Process, ProcessBackend, SymbolProvider, Backend abstraction (ProcessBackend / Process traits), Linux backend (future), Phase 0: Project setup (+3 more)

### Community 23 - "Product Docs And Website"
Cohesion: 0.26
Nodes (12): memx Architecture, memx website landing page, Website build from source section, Website command line section, data-copy clipboard handler, How it works: Open, Map, Read, Decode, memx Implementation Plan, CLI commands (ps, regions, read, inspect, symbol, search, dump, tui, startup) (+4 more)

### Community 24 - "Bitness And Test Coverage"
Cohesion: 0.22
Nodes (11): Key constraints, WOW64 / 32-bit target support (IsWow64Process2), select() accessible tab switcher, Website screenshot tour (Browse, Symbols, Dump, Settings, Compact), Testing strategy (unit, integration, bitness, negative, manual), memx-fixture known-value test process, Snapshot dumps (.dmp for WinDbg), x64 and x86 builds (+3 more)

### Community 25 - "Memory Search"
Cohesion: 0.36
Nodes (10): matches_at(), parse_hex_pattern(), patterns(), Option, Process, RegionMap, Result, Vec (+2 more)

### Community 26 - "Typing And Symbol Design"
Cohesion: 0.24
Nodes (10): MSVC RTTI class identification, Symbol Resolver (DbgHelp / PDB), Type Decoder (exact, user-chosen), Type Inference Engine (heuristic), Phase 4: Explicit type decoding, Phase 6: Automatic type inference (memx inspect), Phase 7: Symbols and RTTI, Address expressions (hex, module+0xOFFSET, module!symbol) (+2 more)

### Community 27 - "MSVC RTTI Decoding"
Cohesion: 0.47
Nodes (8): class_from_vtable(), class_of_object(), demangle_type_name(), read_ptr(), InferCtx, Option, String, u32_at()

### Community 28 - "Front-end And IPC Design"
Cohesion: 0.29
Nodes (8): Serialized inspection worker (bounded queue of 16), IPC boundary (memory_request, startup_status, startup_set), Shared Rust library and Session, Tauri 2 desktop front-end (desktop-ui feature), TUI front-end (ratatui, feature tui), IPC wire format (hex-string addresses, null unreadable bytes), Phase 8: Interactive TUI, Microsoft Edge WebView2 prerequisite

### Community 29 - "Privilege And Deployment Plan"
Cohesion: 0.32
Nodes (8): Separate kernel/boot architecture (service broker + signed WDK driver, future), Sign-in startup via Task Scheduler (highest run level), Administrator and snapshot delivery, Remaining deployment work (code signing, startup cleanup, kernel support), Risks and mitigations, Administrator launch via UAC, Settings dialog (sign-in startup, PDB symbols, symbol path), SHA256SUMS.txt checksums

### Community 30 - "Versioning And CI Workflows"
Cohesion: 0.46
Nodes (8): Versioning and releases (SemVer, Cargo.toml source of truth), version:check / version:set (scripts/version.mjs), Pull request workflow, PR Version job (require unreleased version), Release workflow, Release build job (exe + NSIS installer), Detect merged pull request job, Publish GitHub release job

### Community 31 - "Version Script"
Cohesion: 0.61
Nodes (7): check(), path(), read(), replace(), root, set(), versions()

### Community 32 - "Tauri Capabilities"
Cohesion: 0.33
Nodes (5): description, identifier, permissions, $schema, windows

### Community 33 - "Access Boundaries"
Cohesion: 0.47
Nodes (6): Protected Processes (PP/PPL) boundary, Process Handle / Access (OwnedHandle), SeDebugPrivilege, Website access limits section, Phase 1: Find and open the process, Access and safety principles

### Community 34 - "Known-Value Fixture"
Cohesion: 0.60
Nodes (4): FixtureData, main(), narrow16(), wide16()

## Knowledge Gaps
- **143 isolated node(s):** `$schema`, `identifier`, `description`, `windows`, `permissions` (+138 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Protect` connect `Memory Data Model` to `Windows Process Backend`, `Type Inference Engine`, `CLI Command Dispatch`, `Region Labeling`, `Region Map Lookup`?**
  _High betweenness centrality (0.222) - this node is a cross-community bridge._
- **Why does `Serialize` connect `CLI Command Dispatch` to `Exact Type Decoding`, `Type Inference Engine`, `Memory Data Model`, `Elevated Startup Scheduling`?**
  _High betweenness centrality (0.209) - this node is a cross-community bridge._
- **Why does `run()` connect `CLI Command Dispatch` to `Session And Target Resolution`?**
  _High betweenness centrality (0.093) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `Protect` (e.g. with `rtti_vtable_x64()` and `labels_modules_stacks_heaps()`) actually correct?**
  _`Protect` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `$schema`, `identifier`, `description` to the rest of the system?**
  _144 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Windows Process Backend` be split into smaller, more focused modules?**
  _Cohesion score 0.07120500782472614 - nodes in this community are weakly interconnected._
- **Should `Memory Data Model` be split into smaller, more focused modules?**
  _Cohesion score 0.09219858156028368 - nodes in this community are weakly interconnected._