//! DbgHelp-backed symbol provider: names, addresses and PDB type layouts.

use std::cell::RefCell;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{addr_of, null, null_mut};

use anyhow::{anyhow, Result};
use windows_sys::Win32::Foundation::{DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SymCleanup, SymEnumSymbolsW, SymFromAddrW, SymFromNameW, SymGetTypeInfo, SymInitializeW,
    SymLoadModuleExW, SymSetOptions, SYMBOL_INFOW, TI_FINDCHILDREN, TI_GET_BASETYPE,
    TI_GET_CHILDRENCOUNT, TI_GET_COUNT, TI_GET_DATAKIND, TI_GET_LENGTH, TI_GET_OFFSET,
    TI_GET_SYMNAME, TI_GET_SYMTAG, TI_GET_TYPE, TI_GET_TYPEID, IMAGEHLP_SYMBOL_TYPE_INFO,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::{wide, OwnedHandle};
use crate::backend::SymbolProvider;
use crate::decode::DataType;
use crate::model::{Field, Module, SymbolHit, TypeDesc};

const SYMOPT_UNDNAME: u32 = 0x2;
const SYMOPT_DEFERRED_LOADS: u32 = 0x4;
const SYMOPT_FAIL_CRITICAL_ERRORS: u32 = 0x200;
const SYMOPT_AUTO_PUBLICS: u32 = 0x10000;
const SYMOPT_NO_PROMPTS: u32 = 0x80000;

const SYM_TAG_UDT: u32 = 11;
const SYM_TAG_ENUM: u32 = 12;
const SYM_TAG_POINTER: u32 = 14;
const SYM_TAG_ARRAY: u32 = 15;
const SYM_TAG_BASE: u32 = 16;
const SYM_TAG_TYPEDEF: u32 = 17;
const SYM_TAG_DATA: u32 = 7;
const DATA_IS_MEMBER: u32 = 7;

const MAX_NAME: usize = 1024;
const MAX_DEPTH: u32 = 4;
const MAX_FIELDS: u32 = 512;

#[repr(C, align(8))]
struct SymBuf {
    info: SYMBOL_INFOW,
    _name: [u16; MAX_NAME],
}

impl SymBuf {
    fn new() -> Box<Self> {
        let mut b: Box<Self> = Box::new(unsafe { zeroed() });
        b.info.SizeOfStruct = size_of::<SYMBOL_INFOW>() as u32;
        b.info.MaxNameLen = MAX_NAME as u32;
        b
    }
}

fn info_name(info: &SYMBOL_INFOW) -> String {
    let len = (info.NameLen as usize).min(MAX_NAME);
    // Name is a flexible array member; the caller's buffer extends past the struct.
    let p = addr_of!(info.Name) as *const u16;
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

pub struct DbgHelp {
    h: OwnedHandle,
    /// (base, size, display name)
    modules: Vec<(u64, u64, String)>,
    type_cache: RefCell<std::collections::HashMap<(u64, u32), TypeDesc>>,
}

impl DbgHelp {
    pub fn new(target: HANDLE, search_path: Option<&str>, modules: &[Module]) -> Result<Self> {
        let _guard = super::dbghelp_lock();
        // DbgHelp keys sessions by handle value, so use a private duplicate.
        let mut dup: HANDLE = null_mut();
        let ok = unsafe {
            DuplicateHandle(GetCurrentProcess(), target, GetCurrentProcess(), &mut dup, 0, 0, DUPLICATE_SAME_ACCESS)
        } != 0;
        if !ok {
            return Err(anyhow!("DuplicateHandle failed: {}", std::io::Error::last_os_error()));
        }
        let h = OwnedHandle(dup);
        unsafe {
            SymSetOptions(
                SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_AUTO_PUBLICS | SYMOPT_NO_PROMPTS,
            )
        };
        // Many PDB references are bare file names (e.g. Rust's /PDBALTPATH), so also search next to each image.
        let mut parts: Vec<String> = search_path.map(str::to_string).into_iter().collect();
        for m in modules {
            if let Some((dir, _)) = m.path.rsplit_once('\\') {
                if !parts.iter().any(|p| p.eq_ignore_ascii_case(dir)) {
                    parts.push(dir.to_string());
                }
            }
        }
        let path = wide(&parts.join(";"));
        if unsafe { SymInitializeW(h.0, path.as_ptr(), 0) } == 0 {
            return Err(anyhow!("SymInitializeW failed: {}", std::io::Error::last_os_error()));
        }
        let mut mods = Vec::new();
        for m in modules {
            let image = wide(&m.path);
            let stem = wide(&m.stem());
            unsafe {
                SymLoadModuleExW(h.0, null_mut(), image.as_ptr(), stem.as_ptr(), m.base, m.size as u32, null(), 0)
            };
            mods.push((m.base, m.size, m.name.clone()));
        }
        Ok(Self { h, modules: mods, type_cache: RefCell::new(Default::default()) })
    }

    fn module_name(&self, addr: u64) -> Option<&str> {
        self.modules
            .iter()
            .find(|(b, s, _)| addr >= *b && addr < b + s)
            .map(|(_, _, n)| n.as_str())
    }

    fn hit_from_info(&self, info: &SYMBOL_INFOW, displacement: u64) -> SymbolHit {
        let raw = info_name(info);
        let name = match self.module_name(info.Address) {
            Some(m) => format!("{m}!{raw}"),
            None => raw,
        };
        let is_data = info.Tag == SYM_TAG_DATA;
        let ty = (is_data && info.TypeIndex != 0)
            .then(|| self.describe_type(info.ModBase, info.TypeIndex, 0))
            .flatten();
        let size = if info.Size != 0 { info.Size as u64 } else { ty.as_ref().map_or(0, |t| t.size()) };
        SymbolHit { name, address: info.Address, size, displacement, is_data, ty }
    }

    fn ti<T: Default>(&self, base: u64, id: u32, kind: IMAGEHLP_SYMBOL_TYPE_INFO) -> Option<T> {
        let mut v = T::default();
        let ok = unsafe { SymGetTypeInfo(self.h.0, base, id, kind, &mut v as *mut T as *mut c_void) } != 0;
        ok.then_some(v)
    }

    fn ti_name(&self, base: u64, id: u32) -> Option<String> {
        let mut p: *mut u16 = null_mut();
        let ok = unsafe { SymGetTypeInfo(self.h.0, base, id, TI_GET_SYMNAME, &mut p as *mut _ as *mut c_void) } != 0;
        if !ok || p.is_null() {
            return None;
        }
        let mut n = 0;
        while unsafe { *p.add(n) } != 0 && n < 4096 {
            n += 1;
        }
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) });
        unsafe { LocalFree(p as *mut c_void) };
        Some(s)
    }

    fn describe_type(&self, base: u64, id: u32, depth: u32) -> Option<TypeDesc> {
        if let Some(t) = self.type_cache.borrow().get(&(base, id)) {
            return Some(t.clone());
        }
        let t = self.describe_type_uncached(base, id, depth)?;
        if depth == 0 {
            self.type_cache.borrow_mut().insert((base, id), t.clone());
        }
        Some(t)
    }

    fn describe_type_uncached(&self, base: u64, id: u32, depth: u32) -> Option<TypeDesc> {
        let tag: u32 = self.ti(base, id, TI_GET_SYMTAG)?;
        let size: u64 = self.ti(base, id, TI_GET_LENGTH).unwrap_or(0);
        let ty = match tag {
            SYM_TAG_BASE => {
                let bt: u32 = self.ti(base, id, TI_GET_BASETYPE).unwrap_or(0);
                let (name, decode) = base_type(bt, size);
                TypeDesc::Base { name, size, decode }
            }
            SYM_TAG_POINTER => {
                let target = self
                    .ti::<u32>(base, id, TI_GET_TYPE)
                    .and_then(|t| self.type_name(base, t, depth + 1))
                    .unwrap_or_else(|| "void".into());
                TypeDesc::Pointer { size, target }
            }
            SYM_TAG_ARRAY => {
                let elem = self
                    .ti::<u32>(base, id, TI_GET_TYPE)
                    .and_then(|t| self.describe_type(base, t, depth + 1))
                    .unwrap_or(TypeDesc::Other { name: "?".into(), size: 0 });
                let count: u32 = self.ti(base, id, TI_GET_COUNT).unwrap_or(0);
                TypeDesc::Array { elem: Box::new(elem), count: count as u64, size }
            }
            SYM_TAG_TYPEDEF => {
                let t: u32 = self.ti(base, id, TI_GET_TYPE)?;
                return self.describe_type(base, t, depth);
            }
            SYM_TAG_ENUM => TypeDesc::Enum { name: self.ti_name(base, id).unwrap_or_default(), size },
            SYM_TAG_UDT => {
                let name = self.ti_name(base, id).unwrap_or_default();
                let fields = if depth < MAX_DEPTH { self.fields(base, id, depth) } else { Vec::new() };
                TypeDesc::Struct { name, size, fields }
            }
            _ => TypeDesc::Other { name: self.ti_name(base, id).unwrap_or_else(|| format!("tag{tag}")), size },
        };
        Some(ty)
    }

    fn type_name(&self, base: u64, id: u32, depth: u32) -> Option<String> {
        let tag: u32 = self.ti(base, id, TI_GET_SYMTAG)?;
        match tag {
            SYM_TAG_UDT | SYM_TAG_ENUM => self.ti_name(base, id),
            SYM_TAG_POINTER if depth < MAX_DEPTH => {
                let inner = self.ti::<u32>(base, id, TI_GET_TYPE).and_then(|t| self.type_name(base, t, depth + 1));
                Some(format!("{}*", inner.unwrap_or_else(|| "void".into())))
            }
            SYM_TAG_TYPEDEF => self.ti_name(base, id),
            _ => self.describe_type_uncached(base, id, MAX_DEPTH).map(|t| t.name()),
        }
    }

    fn fields(&self, base: u64, id: u32, depth: u32) -> Vec<Field> {
        let count: u32 = self.ti(base, id, TI_GET_CHILDRENCOUNT).unwrap_or(0).min(MAX_FIELDS);
        if count == 0 {
            return Vec::new();
        }
        // TI_FINDCHILDREN_PARAMS { Count, Start, ChildId[Count] }
        let mut params = vec![0u32; 2 + count as usize];
        params[0] = count;
        let ok = unsafe { SymGetTypeInfo(self.h.0, base, id, TI_FINDCHILDREN, params.as_mut_ptr() as *mut c_void) } != 0;
        if !ok {
            return Vec::new();
        }
        let mut out = Vec::new();
        for &child in &params[2..] {
            if self.ti::<u32>(base, child, TI_GET_SYMTAG) != Some(SYM_TAG_DATA) {
                continue;
            }
            if self.ti::<u32>(base, child, TI_GET_DATAKIND) != Some(DATA_IS_MEMBER) {
                continue;
            }
            let Some(offset) = self.ti::<u32>(base, child, TI_GET_OFFSET) else { continue };
            let name = self.ti_name(base, child).unwrap_or_default();
            let ty = self
                .ti::<u32>(base, child, TI_GET_TYPEID)
                .and_then(|t| self.describe_type(base, t, depth + 1))
                .unwrap_or(TypeDesc::Other { name: "?".into(), size: 0 });
            out.push(Field { name, offset: offset as u64, ty });
        }
        out.sort_by_key(|f| f.offset);
        out
    }
}

fn base_type(bt: u32, size: u64) -> (String, Option<DataType>) {
    use DataType::*;
    let dt = match (bt, size) {
        (2 | 34, 1) => return ("char".into(), Some(I8)),
        (3 | 32, 2) => return ("wchar_t".into(), Some(U16)),
        (33, 4) => return ("char32_t".into(), Some(U32)),
        (10, 1) => Bool,
        (6 | 13, 1) => I8,
        (6 | 13, 2) => I16,
        (6 | 13, 4) => I32,
        (6 | 13, 8) => I64,
        (7 | 14, 1) => U8,
        (7 | 14, 2) => U16,
        (7 | 14, 4) => U32,
        (7 | 14, 8) => U64,
        (8, 4) => F32,
        (8, 8) => F64,
        (31, 4) => return ("HRESULT".into(), Some(U32)),
        (1, _) => return ("void".into(), None),
        _ => return (format!("basetype{bt}"), None),
    };
    (dt.name().to_string(), Some(dt))
}

struct EnumCtx<'a> {
    owner: &'a DbgHelp,
    out: Vec<SymbolHit>,
}

unsafe extern "system" fn enum_cb(info: *const SYMBOL_INFOW, _size: u32, ctx: *const c_void) -> i32 {
    let ctx = &mut *(ctx as *mut EnumCtx);
    let info = &*info;
    if info.Tag == SYM_TAG_DATA {
        let hit = ctx.owner.hit_from_info(info, 0);
        ctx.out.push(hit);
    }
    (ctx.out.len() < 100_000) as i32
}

impl SymbolProvider for DbgHelp {
    fn lookup_addr(&self, addr: u64) -> Option<SymbolHit> {
        let _guard = super::dbghelp_lock();
        let mut buf = SymBuf::new();
        let mut disp = 0u64;
        if unsafe { SymFromAddrW(self.h.0, addr, &mut disp, &mut buf.info) } == 0 {
            return None;
        }
        Some(self.hit_from_info(&buf.info, disp))
    }

    fn lookup_name(&self, name: &str) -> Option<SymbolHit> {
        let _guard = super::dbghelp_lock();
        // DbgHelp module names have no extension: "kernel32!Foo", not "kernel32.dll!Foo".
        let query = match name.split_once('!') {
            Some((m, s)) => {
                let m = m.rsplit_once('.').map_or(m, |(stem, _)| stem);
                format!("{m}!{s}")
            }
            None => name.to_string(),
        };
        let w = wide(&query);
        let mut buf = SymBuf::new();
        if unsafe { SymFromNameW(self.h.0, w.as_ptr(), &mut buf.info) } == 0 {
            return None;
        }
        Some(self.hit_from_info(&buf.info, 0))
    }

    fn globals(&self, module_base: u64, mask: &str) -> Vec<SymbolHit> {
        let _guard = super::dbghelp_lock();
        let w = wide(mask);
        let mut ctx = EnumCtx { owner: self, out: Vec::new() };
        unsafe {
            SymEnumSymbolsW(self.h.0, module_base, w.as_ptr(), Some(enum_cb), &mut ctx as *mut _ as *const c_void)
        };
        let mut out = ctx.out;
        out.sort_by_key(|h| h.address);
        out
    }
}

impl Drop for DbgHelp {
    fn drop(&mut self) {
        let _guard = super::dbghelp_lock();
        unsafe { SymCleanup(self.h.0) };
    }
}
