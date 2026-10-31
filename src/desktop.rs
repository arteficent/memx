use std::sync::mpsc::{self, SyncSender};

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::backend::{self, ProcessBackend};
use crate::decode::{self, DataType};
use crate::infer;
use crate::model::MemState;
use crate::session::{resolve_target, Session, SessionOptions};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Runtime {},
    Processes {},
    Attach { pid: u32, symbols: bool, symbol_path: Option<String> },
    Detach {},
    Refresh {},
    Regions { offset: usize, limit: usize, readable: bool, filter: String },
    Modules {},
    Globals { module: String, filter: String },
    Read { address: String, len: usize, data_type: String },
    Dump { path: String },
}

type Reply = std::result::Result<Value, String>;
type Job = (Request, mpsc::Sender<Reply>);

#[derive(Clone)]
pub struct DesktopService {
    sender: SyncSender<Job>,
}

impl DesktopService {
    pub fn start() -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(16);
        std::thread::Builder::new().name("memx-inspection".into()).spawn(move || {
            let backend = backend::native();
            let mut session = None;
            for (request, reply) in receiver {
                let result = match &backend {
                    Ok(backend) => dispatch(&**backend, &mut session, request),
                    Err(error) => Err(anyhow!("{error:#}")),
                };
                let _ = reply.send(result.map_err(|error| format!("{error:#}")));
            }
        })?;
        Ok(Self { sender })
    }

    pub fn request(&self, request: Request) -> Reply {
        let (sender, receiver) = mpsc::channel();
        self.sender.try_send((request, sender)).map_err(|error| format!("inspection worker: {error}"))?;
        receiver.recv().map_err(|error| format!("inspection worker stopped: {error}"))?
    }
}

fn snapshot(session: &Session) -> Value {
    let regions = session.map.regions();
    json!({
        "info": session.info(),
        "region_count": regions.iter().filter(|region| region.state != MemState::Free).count(),
        "readable_count": regions.iter().filter(|region| region.is_readable()).count(),
        "committed_bytes": regions.iter().filter(|region| region.state == MemState::Commit).map(|region| region.size).sum::<u64>(),
        "modules": session.modules.len(),
        "threads": session.threads.len(),
        "warnings": session.warnings,
    })
}

fn validate_read(address: u64, len: usize, pointer_size: usize) -> Result<()> {
    if !(1..=4096).contains(&len) {
        bail!("read length must be between 1 and 4096 bytes");
    }
    let end = address.checked_add(len as u64 - 1).ok_or_else(|| anyhow!("address range overflow"))?;
    if pointer_size == 4 && end > u32::MAX as u64 {
        bail!("address is outside the 32-bit target address space");
    }
    Ok(())
}

fn dispatch(backend: &dyn ProcessBackend, active: &mut Option<Session>, request: Request) -> Result<Value> {
    match request {
        Request::Runtime {} => return Ok(json!({ "elevated": crate::startup::is_elevated(), "mode": "user", "kernel_driver": false, "version": env!("CARGO_PKG_VERSION"), "arch": std::env::consts::ARCH })),
        Request::Processes {} => return Ok(serde_json::to_value(backend.list_catalog()?)?),
        Request::Attach { pid, symbols, symbol_path } => {
            if symbol_path.as_ref().is_some_and(|path| path.len() > 2048) {
                bail!("symbol path is too long");
            }
            *active = None;
            let target = resolve_target(backend, Some(pid), None)?;
            let session = Session::open(backend, &target, SessionOptions {
                no_symbols: !symbols,
                symbol_path,
                ..SessionOptions::default()
            })?;
            let result = snapshot(&session);
            *active = Some(session);
            return Ok(result);
        }
        Request::Detach {} => {
            *active = None;
            return Ok(Value::Null);
        }
        _ => {}
    }
    let session = active.as_mut().ok_or_else(|| anyhow!("select a readable process first"))?;
    match request {
        Request::Dump { path } => {
            if path.len() > 32768 || path.contains('\0') { bail!("invalid dump path"); }
            Ok(serde_json::to_value(session.proc.dump(std::path::Path::new(&path))?)?)
        }
        Request::Refresh {} => {
            session.refresh()?;
            Ok(snapshot(session))
        }
        Request::Regions { offset, limit, readable, filter } => {
            if !(1..=256).contains(&limit) || filter.len() > 512 {
                bail!("invalid region page (limit 1..256, filter up to 512 characters)");
            }
            let filter = filter.to_lowercase();
            let regions: Vec<_> = session.map.regions().iter()
                .filter(|region| region.state != MemState::Free && (!readable || region.is_readable()))
                .filter(|region| filter.is_empty() || format!("{} {} 0x{:x}", region.kind, region.label.as_deref().unwrap_or(""), region.base).to_lowercase().contains(&filter))
                .collect();
            Ok(json!({ "total": regions.len(), "offset": offset, "regions": regions.into_iter().skip(offset).take(limit).collect::<Vec<_>>() }))
        }
        Request::Modules {} => Ok(serde_json::to_value(&session.modules)?),
        Request::Globals { module, filter } => {
            if filter.len() > 512 {
                bail!("symbol filter is too long");
            }
            let module = session.find_module(&module).cloned().ok_or_else(|| anyhow!("module not loaded"))?;
            let symbols = session.symbols().ok_or_else(|| anyhow!("symbols unavailable; enable PDB symbols and reopen the process"))?;
            let hits = symbols.globals(module.base, &filter);
            Ok(json!({ "total": hits.len(), "symbols": hits.into_iter().take(256).collect::<Vec<_>>(), "warnings": session.warnings }))
        }
        Request::Read { address, len, data_type } => {
            if address.len() > 512 {
                bail!("address expression is too long");
            }
            let chosen = if data_type == "auto" { None } else { Some(data_type.parse::<DataType>()?) };
            validate_read(0, len, session.ptr_size())?;
            let address = session.resolve_addr(&address)?;
            validate_read(address, len, session.ptr_size())?;
            session.clear_reads();
            let result = session.read(address, len);
            let bytes: Vec<_> = result.bytes.iter().zip(&result.valid).map(|(byte, valid)| valid.then_some(*byte)).collect();
            let values = if let Some(data_type) = chosen {
                let stride = data_type.size(session.ptr_size());
                let mut values = Vec::new();
                if data_type.is_string() || data_type == DataType::Hex {
                    if let Some(value) = decode::decode(data_type, result.valid_prefix(), session.ptr_size()) {
                        values.push(json!({ "addr": format!("0x{address:x}"), "len": result.valid_prefix().len(), "type": data_type.name(), "value": value, "source": "user", "confidence": "chosen" }));
                    }
                } else {
                    for (index, chunk) in result.bytes.chunks_exact(stride).enumerate() {
                        let offset = index * stride;
                        let value = if result.valid[offset..offset + stride].iter().all(|valid| *valid) {
                            decode::decode(data_type, chunk, session.ptr_size()).unwrap_or_default()
                        } else { "??".into() };
                        values.push(json!({ "addr": format!("0x{:x}", address + offset as u64), "len": stride, "type": data_type.name(), "value": value, "source": "user", "confidence": "chosen" }));
                    }
                }
                Value::Array(values)
            } else {
                serde_json::to_value(infer::annotate(session, &result, true))?
            };
            Ok(json!({ "address": format!("0x{address:x}"), "bytes": bytes, "valid_count": result.valid_count(), "values": values, "warnings": session.warnings }))
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_reads_are_bounded_and_target_width_aware() {
        assert!(validate_read(0x1000, 4096, 8).is_ok());
        assert!(validate_read(0, 0, 8).is_err());
        assert!(validate_read(0, 4097, 8).is_err());
        assert!(validate_read(u64::MAX, 2, 8).is_err());
        assert!(validate_read(u32::MAX as u64, 2, 4).is_err());
        assert!(validate_read(0x1_0000_0000, 8, 8).is_ok());
    }

    #[test]
    fn desktop_rejects_unknown_operations_and_fields() {
        assert!(serde_json::from_value::<Request>(json!({ "op": "write" })).is_err());
        assert!(serde_json::from_value::<Request>(json!({ "op": "processes", "extra": true })).is_err());
        assert!(serde_json::from_value::<Request>(json!({ "op": "read", "address": "0x1000", "len": 8, "data_type": "u64" })).is_ok());
    }
}