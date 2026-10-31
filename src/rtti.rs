//! MSVC RTTI: recover C++ class names from vtables.

use crate::decode::read_uint;
use crate::infer::InferCtx;
use crate::model::MemKind;

fn read_ptr(ctx: &mut dyn InferCtx, addr: u64) -> Option<u64> {
    let ps = ctx.ptr_size();
    let b = ctx.peek(addr, ps)?;
    (b.len() == ps).then(|| read_uint(&b, ps))
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Returns the class name if `vtable` points at an MSVC vftable with a valid CompleteObjectLocator.
pub fn class_from_vtable(ctx: &mut dyn InferCtx, vtable: u64) -> Option<String> {
    let ps = ctx.ptr_size() as u64;
    let r = ctx.region(vtable)?;
    if r.kind != MemKind::Image || r.protect.writable() || r.protect.executable() || !r.is_readable() {
        return None;
    }
    let module_base = ctx.module_base(vtable)?;
    let col = read_ptr(ctx, vtable.checked_sub(ps)?)?;
    let b = ctx.peek(col, 24)?;
    if b.len() < 20 {
        return None;
    }
    let signature = u32_at(&b, 0);
    let td = if ps == 8 {
        // x64 COL uses image-relative offsets and records its own RVA.
        if signature != 1 || b.len() < 24 || module_base + u32_at(&b, 20) as u64 != col {
            return None;
        }
        module_base + u32_at(&b, 12) as u64
    } else {
        if signature != 0 {
            return None;
        }
        u32_at(&b, 12) as u64
    };
    let name = ctx.peek(td + 2 * ps, 256)?;
    let n = name.iter().position(|&c| c == 0)?;
    let raw = std::str::from_utf8(&name[..n]).ok()?;
    raw.starts_with(".?A").then(|| demangle_type_name(raw))
}

pub fn class_of_object(ctx: &mut dyn InferCtx, obj: u64) -> Option<String> {
    let vt = read_ptr(ctx, obj)?;
    class_from_vtable(ctx, vt)
}

/// `.?AVFoo@ns@@` -> `ns::Foo`. Templates are returned undecorated as-is.
pub fn demangle_type_name(raw: &str) -> String {
    let Some(body) = [".?AV", ".?AU", ".?AW4"].iter().find_map(|p| raw.strip_prefix(p)) else {
        return raw.to_string();
    };
    let body = body.strip_suffix("@@").unwrap_or(body);
    if body.contains('?') || body.contains('$') {
        return raw.to_string();
    }
    let parts: Vec<&str> = body.split('@').filter(|s| !s.is_empty()).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangle() {
        assert_eq!(demangle_type_name(".?AVFoo@@"), "Foo");
        assert_eq!(demangle_type_name(".?AVWidget@ui@app@@"), "app::ui::Widget");
        assert_eq!(demangle_type_name(".?AUPoint@@"), "Point");
        assert_eq!(demangle_type_name(".?AV?$vector@H@std@@"), ".?AV?$vector@H@std@@");
    }
}
