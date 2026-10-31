//! Type annotation of raw memory: exact (symbols / RTTI) where possible, heuristic otherwise.

use serde::Serialize;

use crate::decode::{self, fmt_f32, fmt_f64, fmt_ptr, read_uint, DataType};
use crate::model::{ser_hex, MemState, Region, SymbolHit, TypeDesc};
use crate::reader::ReadResult;
use crate::rtti;

pub trait InferCtx {
    fn ptr_size(&self) -> usize;
    fn region(&self, addr: u64) -> Option<&Region>;
    fn module_base(&self, addr: u64) -> Option<u64>;
    /// Valid leading bytes at `addr` (may be shorter than `len`); `None` if nothing is readable.
    fn peek(&mut self, addr: u64, len: usize) -> Option<Vec<u8>>;
    /// Debug-symbol lookup (PDB), if available.
    fn symbol(&mut self, addr: u64) -> Option<SymbolHit>;
    /// Short human description of where `addr` points (symbol, module section, heap, stack...).
    fn describe(&mut self, addr: u64) -> String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Symbol,
    Rtti,
    Heuristic,
}

#[derive(Debug, Clone, Serialize)]
pub struct Annotation {
    #[serde(serialize_with = "ser_hex")]
    pub addr: u64,
    pub len: usize,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: String,
    pub confidence: Confidence,
    pub source: Source,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl Annotation {
    fn new(addr: u64, len: usize, ty: impl Into<String>, value: impl Into<String>, c: Confidence, s: Source) -> Self {
        Self { addr, len, ty: ty.into(), value: value.into(), confidence: c, source: s, field: None }
    }
}

const MIN_STR: usize = 4;

fn printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Detects a string at the start of `b`. Returns (byte length incl. terminator, quoted value, wide).
pub fn detect_string(b: &[u8], valid: &[bool]) -> Option<(usize, String, bool)> {
    let ok = |i: usize| i < b.len() && valid[i];
    // ASCII / UTF-8
    let mut i = 0;
    while ok(i) && printable(b[i]) {
        i += 1;
    }
    let terminated = ok(i) && b[i] == 0;
    if i >= MIN_STR && (terminated || (i == b.len() && i >= 8)) {
        let s = String::from_utf8_lossy(&b[..i]);
        return Some((i + terminated as usize, format!("{s:?}"), false));
    }
    // UTF-16LE (ASCII / Latin-1 range)
    let mut n = 0;
    while ok(2 * n + 1) && b[2 * n + 1] == 0 && (printable(b[2 * n]) || b[2 * n] >= 0xA0) {
        n += 1;
    }
    let terminated = ok(2 * n + 1) && b[2 * n] == 0 && b[2 * n + 1] == 0;
    if n >= MIN_STR && (terminated || (2 * n + 1 >= b.len() && n >= 8)) {
        let units: Vec<u16> = (0..n).map(|k| b[2 * k] as u16).collect();
        let s = String::from_utf16_lossy(&units);
        return Some((2 * n + 2 * terminated as usize, format!("{s:?}"), true));
    }
    None
}

fn plausible_f64(f: f64) -> bool {
    f.is_normal() && (1e-6..=1e9).contains(&f.abs())
}

fn plausible_f32(f: f32) -> bool {
    f.is_normal() && (1e-6..=1e9).contains(&f.abs())
}

fn nice_f64(f: f64) -> bool {
    plausible_f64(f) && format!("{f}").len() <= 10
}

fn nice_f32(f: f32) -> bool {
    plausible_f32(f) && format!("{f}").len() <= 9
}

fn numeric(addr: u64, b: &[u8], ps: usize) -> Annotation {
    use Confidence::*;
    let h = Source::Heuristic;
    if ps == 8 {
        let v = read_uint(b, 8);
        let (lo, hi) = (v as u32, (v >> 32) as u32);
        let f = f64::from_bits(v);
        let (flo, fhi) = (f32::from_bits(lo), f32::from_bits(hi));
        if hi == 0 {
            return Annotation::new(addr, 8, "int", format!("{v} (0x{v:x})"), Medium, h);
        }
        if (v as i64) < 0 && (v as i64) > -0x1_0000 {
            return Annotation::new(addr, 8, "i64", (v as i64).to_string(), Medium, h);
        }
        if nice_f64(f) {
            return Annotation::new(addr, 8, "f64", fmt_f64(f), Medium, h);
        }
        if lo < 0x1_0000 && hi < 0x1_0000 {
            return Annotation::new(addr, 8, "u32 x2", format!("{lo}, {hi}"), Low, h);
        }
        if nice_f32(flo) && (nice_f32(fhi) || hi == 0) {
            return Annotation::new(addr, 8, "f32 x2", format!("{}, {}", fmt_f32(flo), fmt_f32(fhi)), Medium, h);
        }
        if plausible_f64(f) {
            return Annotation::new(addr, 8, "f64", fmt_f64(f), Low, h);
        }
        Annotation::new(addr, 8, "hex", format!("0x{v:016x}"), Low, h)
    } else {
        let v = read_uint(b, 4) as u32;
        let f = f32::from_bits(v);
        if v < 0x0100_0000 {
            return Annotation::new(addr, 4, "int", format!("{v} (0x{v:x})"), Medium, h);
        }
        if (v as i32) < 0 && (v as i32) > -0x1_0000 {
            return Annotation::new(addr, 4, "i32", (v as i32).to_string(), Medium, h);
        }
        if nice_f32(f) {
            return Annotation::new(addr, 4, "f32", fmt_f32(f), Medium, h);
        }
        if plausible_f32(f) {
            return Annotation::new(addr, 4, "f32", fmt_f32(f), Low, h);
        }
        Annotation::new(addr, 4, "hex", format!("0x{v:08x}"), Low, h)
    }
}

/// Builds the "-> target" description for a pointer value, including RTTI and string previews.
pub fn pointer_target(ctx: &mut dyn InferCtx, v: u64) -> (String, bool) {
    let mut desc = ctx.describe(v);
    let mut rtti_hit = false;
    let (readable, image) = match ctx.region(v) {
        Some(r) => (r.is_readable(), r.kind == crate::model::MemKind::Image),
        None => (false, false),
    };
    if !readable {
        return (desc, false);
    }
    if image {
        if let Some(cls) = rtti::class_from_vtable(ctx, v) {
            return (format!("{cls}::`vftable'"), true);
        }
    } else if let Some(cls) = rtti::class_of_object(ctx, v) {
        desc.push_str(&format!(" (obj: {cls})"));
        rtti_hit = true;
    }
    if let Some(b) = ctx.peek(v, 96) {
        let valid = vec![true; b.len()];
        if let Some((_, s, wide)) = detect_string(&b, &valid) {
            desc.push_str(&format!(" {}{s}", if wide { "L" } else { "" }));
        }
    }
    (desc, rtti_hit)
}

fn try_pointer(ctx: &mut dyn InferCtx, addr: u64, v: u64) -> Option<Annotation> {
    let ps = ctx.ptr_size();
    if v < 0x1_0000 {
        return None;
    }
    let r = ctx.region(v)?;
    if r.state != MemState::Commit {
        return None;
    }
    let aligned = v.is_multiple_of(ps as u64) || r.kind == crate::model::MemKind::Image;
    let is_vtable_candidate = r.kind == crate::model::MemKind::Image && !r.protect.writable();
    let (desc, rtti_hit) = pointer_target(ctx, v);
    let (ty, src) = if rtti_hit && is_vtable_candidate {
        ("vftable*", Source::Rtti)
    } else if rtti_hit {
        ("ptr", Source::Rtti)
    } else {
        ("ptr", Source::Heuristic)
    };
    let conf = if aligned || rtti_hit { Confidence::High } else { Confidence::Medium };
    Some(Annotation::new(addr, ps, ty, format!("{} -> {desc}", fmt_ptr(v, ps)), conf, src))
}

fn leaf_value(ctx: &mut dyn InferCtx, ty: &TypeDesc, b: &[u8]) -> String {
    let ps = ctx.ptr_size();
    match ty {
        TypeDesc::Base { decode: Some(dt), .. } => decode::decode(*dt, b, ps).unwrap_or_default(),
        TypeDesc::Pointer { size, .. } => {
            let n = (*size as usize).clamp(1, 8).min(b.len());
            let v = read_uint(b, n);
            if v == 0 {
                "null".into()
            } else if ctx.region(v).is_some_and(|r| r.state == MemState::Commit) {
                format!("{} -> {}", fmt_ptr(v, n), pointer_target(ctx, v).0)
            } else {
                fmt_ptr(v, n)
            }
        }
        TypeDesc::Enum { size, .. } => {
            let n = (*size as usize).clamp(1, 8).min(b.len());
            read_uint(b, n).to_string()
        }
        TypeDesc::Array { elem, .. } => {
            let es = elem.size() as usize;
            let dt = match &**elem {
                TypeDesc::Base { decode: Some(dt), .. } => Some(*dt),
                _ => None,
            };
            let valid = vec![true; b.len()];
            match (es, dt) {
                (1, _) => match detect_string(b, &valid) {
                    Some((_, s, false)) => s,
                    _ => decode::decode(DataType::Hex, &b[..b.len().min(32)], ps).unwrap_or_default(),
                },
                (2, Some(DataType::U16 | DataType::I16)) if detect_string(b, &valid).is_some_and(|s| s.2) => {
                    detect_string(b, &valid).unwrap().1
                }
                (n, Some(dt)) if n > 0 => {
                    let items: Vec<String> =
                        b.chunks_exact(n).take(16).filter_map(|c| decode::decode(dt, c, ps)).collect();
                    let more = if b.len() / n > 16 { ", ..." } else { "" };
                    format!("[{}{more}]", items.join(", "))
                }
                _ => decode::decode(DataType::Hex, &b[..b.len().min(32)], ps).unwrap_or_default(),
            }
        }
        _ => decode::decode(DataType::Hex, &b[..b.len().min(32)], ps).unwrap_or_default(),
    }
}

fn flatten<'a>(ty: &'a TypeDesc, path: String, off: u64, depth: u32, out: &mut Vec<(String, u64, &'a TypeDesc)>) {
    match ty {
        TypeDesc::Struct { fields, .. } if depth < 4 && !fields.is_empty() => {
            for f in fields {
                flatten(&f.ty, format!("{path}.{}", f.name), off + f.offset, depth + 1, out);
            }
        }
        _ => out.push((path, off, ty)),
    }
}

/// Annotates the part of the data symbol `hit` that overlaps `r`. Returns the end offset consumed.
fn annotate_symbol(ctx: &mut dyn InferCtx, hit: &SymbolHit, r: &ReadResult, out: &mut Vec<Annotation>) -> usize {
    let ty = hit.ty.as_ref().expect("caller checks type");
    let buf_end = r.addr + r.bytes.len() as u64;
    let sym_end = hit.address + hit.size.max(1);
    let mut leaves = Vec::new();
    let short = hit.name.rsplit('!').next().unwrap_or(&hit.name);
    let short = short.rsplit("::").next().unwrap_or(short);
    flatten(ty, short.to_string(), 0, 0, &mut leaves);
    for (path, off, leaf) in leaves {
        let a = hit.address + off;
        let size = leaf.size().max(1);
        if a + size <= r.addr || a >= buf_end {
            continue;
        }
        let start = a.max(r.addr);
        let end = (a + size).min(buf_end);
        let (s, e) = ((start - r.addr) as usize, (end - r.addr) as usize);
        let value = if r.valid[s..e].iter().all(|&v| v) {
            if start == a { leaf_value(ctx, leaf, &r.bytes[s..e]) } else { "(partial)".into() }
        } else {
            "??".into()
        };
        let mut ann = Annotation::new(start, e - s, leaf.name(), value, Confidence::High, Source::Symbol);
        ann.field = Some(path);
        out.push(ann);
    }
    sym_end.min(buf_end).saturating_sub(r.addr) as usize
}

/// Typed annotations for a data symbol whose bytes are in `r`.
pub fn symbol_annotations(ctx: &mut dyn InferCtx, hit: &SymbolHit, r: &ReadResult) -> Vec<Annotation> {
    let mut out = Vec::new();
    if hit.ty.is_some() {
        annotate_symbol(ctx, hit, r, &mut out);
    }
    out
}

/// Annotates `r` slot by slot. Symbols win over RTTI, which wins over heuristics.
pub fn annotate(ctx: &mut dyn InferCtx, r: &ReadResult, use_symbols: bool) -> Vec<Annotation> {
    use Confidence::*;
    let ps = ctx.ptr_size();
    let n = r.bytes.len();
    let mut out: Vec<Annotation> = Vec::new();
    let mut off = 0usize;
    while off < n {
        let addr = r.addr + off as u64;
        if use_symbols && r.valid[off] {
            if let Some(hit) = ctx.symbol(addr) {
                if hit.is_data && hit.ty.is_some() && addr >= hit.address && addr < hit.address + hit.size.max(1) {
                    let consumed = annotate_symbol(ctx, &hit, r, &mut out);
                    if consumed > off {
                        off = consumed;
                        continue;
                    }
                }
            }
        }
        let slot = (ps - (addr % ps as u64) as usize).min(n - off);
        let bytes = &r.bytes[off..off + slot];
        if !r.valid[off..off + slot].iter().all(|&v| v) {
            match out.last_mut() {
                Some(last) if last.ty == "unreadable" && last.addr + last.len as u64 == addr => last.len += slot,
                _ => out.push(Annotation::new(addr, slot, "unreadable", "??", High, Source::Heuristic)),
            }
            off += slot;
            continue;
        }
        if slot < ps {
            out.push(Annotation::new(addr, slot, "hex", decode::hex_bytes(bytes), Low, Source::Heuristic));
            off += slot;
            continue;
        }
        let v = read_uint(bytes, ps);
        if v == 0 {
            match out.last_mut() {
                Some(last) if last.ty == "zero" && last.addr + last.len as u64 == addr => last.len += slot,
                _ => out.push(Annotation::new(addr, slot, "zero", "0", High, Source::Heuristic)),
            }
            off += slot;
            continue;
        }
        if let Some(a) = try_pointer(ctx, addr, v) {
            out.push(a);
            off += slot;
            continue;
        }
        if let Some((len, s, wide)) = detect_string(&r.bytes[off..], &r.valid[off..]) {
            let len = len.min(n - off);
            let conf = if len >= 8 { High } else { Medium };
            out.push(Annotation::new(addr, len, if wide { "wstr" } else { "cstr" }, s, conf, Source::Heuristic));
            off += len.div_ceil(ps) * ps;
            continue;
        }
        out.push(numeric(addr, bytes, ps));
        off += slot;
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{MemKind, Protect};
    use crate::regionmap::{tests::region, RegionMap};

    pub struct Mock {
        pub map: RegionMap,
        pub mem: Vec<(u64, Vec<u8>)>,
        pub ps: usize,
    }

    impl InferCtx for Mock {
        fn ptr_size(&self) -> usize {
            self.ps
        }
        fn region(&self, addr: u64) -> Option<&Region> {
            self.map.find(addr)
        }
        fn module_base(&self, addr: u64) -> Option<u64> {
            self.map.find(addr).filter(|r| r.kind == MemKind::Image).map(|r| r.alloc_base)
        }
        fn peek(&mut self, addr: u64, len: usize) -> Option<Vec<u8>> {
            let (base, data) = self.mem.iter().find(|(b, d)| addr >= *b && addr < b + d.len() as u64)?;
            let o = (addr - base) as usize;
            Some(data[o..(o + len).min(data.len())].to_vec())
        }
        fn symbol(&mut self, _addr: u64) -> Option<SymbolHit> {
            None
        }
        fn describe(&mut self, addr: u64) -> String {
            self.map.find(addr).and_then(|r| r.label.clone()).unwrap_or_else(|| "private".into())
        }
    }

    fn rr(addr: u64, bytes: Vec<u8>) -> ReadResult {
        let valid = vec![true; bytes.len()];
        ReadResult { addr, bytes, valid }
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn classifies_common_slots() {
        let mut heap = region(0x10000, 0x1000);
        heap.label = Some("heap #0".into());
        let mut ctx = Mock { map: RegionMap::new(vec![heap]), mem: vec![(0x10000, b"target\0\0".to_vec())], ps: 8 };
        let mut b = Vec::new();
        b.extend_from_slice(&0xDEADBEEFu64.to_le_bytes());
        b.extend_from_slice(&3.14159f64.to_le_bytes());
        b.extend_from_slice(&0x10000u64.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]);
        b.extend_from_slice(b"hello world\0\0\0\0\0");
        b.extend_from_slice(&(-5i64).to_le_bytes());
        let a = annotate(&mut ctx, &rr(0x5000, b), false);
        let tys: Vec<&str> = a.iter().map(|x| x.ty.as_str()).collect();
        assert_eq!(tys, vec!["int", "f64", "ptr", "zero", "cstr", "i64"]);
        assert_eq!(a[1].value, "3.14159");
        assert!(a[2].value.contains("heap #0"), "{}", a[2].value);
        assert!(a[2].value.contains("\"target\""), "{}", a[2].value);
        assert_eq!(a[3].len, 16);
        assert_eq!(a[4].value, "\"hello world\"");
    }

    #[test]
    fn wide_strings_and_unreadable() {
        let mut ctx = Mock { map: RegionMap::new(vec![]), mem: vec![], ps: 8 };
        let mut b: Vec<u8> = "Hi there\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        b.resize(24, 0);
        b.extend_from_slice(&[0xAA; 8]);
        let mut r = rr(0x1000, b);
        r.valid[24..].iter_mut().for_each(|v| *v = false);
        let a = annotate(&mut ctx, &r, false);
        assert_eq!(a[0].ty, "wstr");
        assert_eq!(a[0].value, "\"Hi there\"");
        assert_eq!(a.last().unwrap().ty, "unreadable");
    }

    #[test]
    fn rtti_vtable_x64() {
        // Module image at 0x40000: vtable @0x41000, COL @0x42000, TypeDescriptor @0x43000.
        let mut img = region(0x40000, 0x4000);
        img.kind = MemKind::Image;
        img.protect = Protect(Protect::READONLY);
        let obj_heap = region(0x10000, 0x1000);
        let mut col = Vec::new();
        col.extend_from_slice(&1u32.to_le_bytes()); // signature
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&0x3000u32.to_le_bytes()); // type descriptor RVA
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&0x2000u32.to_le_bytes()); // self RVA
        let mut td = vec![0u8; 16];
        td.extend_from_slice(b".?AVWidget@ui@@\0");
        let mut ctx = Mock {
            map: RegionMap::new(vec![img, obj_heap]),
            mem: vec![
                (0x40ff8, 0x42000u64.to_le_bytes().to_vec()),
                (0x42000, col),
                (0x43000, td),
                (0x10000, 0x41000u64.to_le_bytes().to_vec()),
            ],
            ps: 8,
        };
        assert_eq!(rtti::class_from_vtable(&mut ctx, 0x41000).as_deref(), Some("ui::Widget"));
        let a = annotate(&mut ctx, &rr(0x5000, 0x10000u64.to_le_bytes().to_vec()), false);
        assert_eq!(a[0].source, Source::Rtti);
        assert!(a[0].value.contains("obj: ui::Widget"), "{}", a[0].value);
    }
}
