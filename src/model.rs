use std::fmt;

use serde::{Serialize, Serializer};

use crate::decode::DataType;

pub fn ser_hex<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{v:x}"))
}

pub fn ser_hex_opt<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => ser_hex(v, s),
        None => s.serialize_none(),
    }
}

pub fn ser_hex_vec<S: Serializer>(v: &[u64], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(v.iter().map(|x| format!("0x{x:x}")))
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub threads: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer_size: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSummary {
    #[serde(flatten)]
    pub info: ProcessInfo,
    pub session_id: Option<u32>,
    pub owner: Option<String>,
    pub category: String,
    pub access: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpReport {
    pub pid: u32,
    pub path: String,
    pub bytes: u64,
    pub capture_started_unix_ms: u64,
    pub capture_completed_unix_ms: u64,
    pub finished_unix_ms: u64,
    pub mode: &'static str,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MemState {
    Commit,
    Reserve,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MemKind {
    Image,
    Mapped,
    Private,
    None,
}

impl fmt::Display for MemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MemKind::Image => "image",
            MemKind::Mapped => "mapped",
            MemKind::Private => "private",
            MemKind::None => "-",
        })
    }
}

impl fmt::Display for MemState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MemState::Commit => "commit",
            MemState::Reserve => "reserve",
            MemState::Free => "free",
        })
    }
}

/// Page protection using Windows `PAGE_*` semantics (other backends map onto these).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Protect(pub u32);

impl Protect {
    pub const READONLY: u32 = 0x02;
    pub const READWRITE: u32 = 0x04;
    pub const WRITECOPY: u32 = 0x08;
    pub const EXECUTE: u32 = 0x10;
    pub const EXECUTE_READ: u32 = 0x20;
    pub const EXECUTE_READWRITE: u32 = 0x40;
    pub const EXECUTE_WRITECOPY: u32 = 0x80;
    pub const GUARD: u32 = 0x100;

    fn base(self) -> u32 {
        self.0 & 0xFF
    }
    pub fn guard(self) -> bool {
        self.0 & Self::GUARD != 0
    }
    pub fn readable(self) -> bool {
        !self.guard() && self.base_readable()
    }
    fn base_readable(self) -> bool {
        matches!(
            self.base(),
            Self::READONLY
                | Self::READWRITE
                | Self::WRITECOPY
                | Self::EXECUTE_READ
                | Self::EXECUTE_READWRITE
                | Self::EXECUTE_WRITECOPY
        )
    }
    pub fn writable(self) -> bool {
        matches!(
            self.base(),
            Self::READWRITE | Self::WRITECOPY | Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY
        )
    }
    pub fn executable(self) -> bool {
        matches!(
            self.base(),
            Self::EXECUTE | Self::EXECUTE_READ | Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY
        )
    }
    fn copy_on_write(self) -> bool {
        matches!(self.base(), Self::WRITECOPY | Self::EXECUTE_WRITECOPY)
    }
}

impl fmt::Display for Protect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("");
        }
        let r = if self.base_readable() { 'R' } else { '-' };
        let w = if self.copy_on_write() { 'C' } else if self.writable() { 'W' } else { '-' };
        let x = if self.executable() { 'X' } else { '-' };
        write!(f, "{r}{w}{x}")?;
        if self.guard() {
            f.write_str("G")?;
        }
        Ok(())
    }
}

impl Serialize for Protect {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    #[serde(serialize_with = "ser_hex")]
    pub base: u64,
    pub size: u64,
    pub state: MemState,
    pub protect: Protect,
    #[serde(serialize_with = "ser_hex")]
    pub alloc_base: u64,
    pub alloc_protect: Protect,
    pub kind: MemKind,
    pub label: Option<String>,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
    pub fn is_readable(&self) -> bool {
        self.state == MemState::Commit && self.protect.readable()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    #[serde(serialize_with = "ser_hex")]
    pub base: u64,
    pub size: u64,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Module {
    pub name: String,
    #[serde(serialize_with = "ser_hex")]
    pub base: u64,
    pub size: u64,
    pub path: String,
    pub sections: Vec<Section>,
    #[serde(skip)]
    pub export_dir: Option<(u32, u32)>,
}

impl Module {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| addr >= s.base && addr < s.base + s.size.max(1))
    }
    /// Module name without extension, lowercase.
    pub fn stem(&self) -> String {
        let n = self.name.to_ascii_lowercase();
        match n.rfind('.') {
            Some(i) => n[..i].to_string(),
            None => n,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StackRange {
    #[serde(serialize_with = "ser_hex")]
    pub base: u64,
    #[serde(serialize_with = "ser_hex")]
    pub limit: u64,
    pub wow64: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub tid: u32,
    #[serde(serialize_with = "ser_hex")]
    pub teb: u64,
    pub stacks: Vec<StackRange>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessExtras {
    #[serde(serialize_with = "ser_hex_opt")]
    pub peb: Option<u64>,
    #[serde(serialize_with = "ser_hex_opt")]
    pub peb32: Option<u64>,
    #[serde(serialize_with = "ser_hex_vec")]
    pub heaps: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub name: String,
    pub offset: u64,
    #[serde(rename = "type")]
    pub ty: TypeDesc,
}

/// Type information recovered from debug symbols.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum TypeDesc {
    Base { name: String, size: u64, decode: Option<DataType> },
    Pointer { size: u64, target: String },
    Array { elem: Box<TypeDesc>, count: u64, size: u64 },
    Struct { name: String, size: u64, fields: Vec<Field> },
    Enum { name: String, size: u64 },
    Other { name: String, size: u64 },
}

impl TypeDesc {
    pub fn size(&self) -> u64 {
        match self {
            TypeDesc::Base { size, .. }
            | TypeDesc::Pointer { size, .. }
            | TypeDesc::Array { size, .. }
            | TypeDesc::Struct { size, .. }
            | TypeDesc::Enum { size, .. }
            | TypeDesc::Other { size, .. } => *size,
        }
    }
    pub fn name(&self) -> String {
        match self {
            TypeDesc::Base { name, .. }
            | TypeDesc::Struct { name, .. }
            | TypeDesc::Enum { name, .. }
            | TypeDesc::Other { name, .. } => name.clone(),
            TypeDesc::Pointer { target, .. } => format!("{target}*"),
            TypeDesc::Array { elem, count, .. } => format!("{}[{count}]", elem.name()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolHit {
    pub name: String,
    #[serde(serialize_with = "ser_hex")]
    pub address: u64,
    pub size: u64,
    #[serde(skip)]
    pub displacement: u64,
    pub is_data: bool,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub ty: Option<TypeDesc>,
}
