//! Attaches human-readable meaning to regions (module sections, stacks, heaps, PEB/TEB, mapped files).

use std::collections::HashMap;

use crate::model::{MemKind, MemState, Module, ProcessExtras, Region, ThreadInfo};

fn index_of(regions: &[Region], addr: u64) -> Option<usize> {
    let i = regions.partition_point(|r| r.base <= addr);
    (i > 0 && regions[i - 1].contains(addr)).then(|| i - 1)
}

/// `regions` must be sorted by base.
pub fn apply(
    regions: &mut [Region],
    modules: &[Module],
    threads: &[ThreadInfo],
    extras: &ProcessExtras,
    mapped_name: &dyn Fn(u64) -> Option<String>,
) {
    let mut labels: Vec<Vec<String>> = vec![Vec::new(); regions.len()];

    // Stack allocations: every region sharing the allocation base belongs to the stack.
    let mut by_alloc: HashMap<u64, String> = HashMap::new();
    let mut stack_ranges = Vec::new();
    for t in threads {
        for s in &t.stacks {
            let suffix = if s.wow64 { " (wow64)" } else { "" };
            let name = format!("stack T{}{suffix}", t.tid);
            if let Some(i) = index_of(regions, s.limit) {
                by_alloc.insert(regions[i].alloc_base, name.clone());
            }
            stack_ranges.push((s.limit, s.base, name));
        }
    }
    for (i, h) in extras.heaps.iter().enumerate() {
        let name = if i == 0 { "heap #0 (default)".to_string() } else { format!("heap #{i}") };
        by_alloc.entry(*h).or_insert(name);
    }

    let mut mapped_cache: HashMap<u64, Option<String>> = HashMap::new();
    for (i, r) in regions.iter().enumerate() {
        if r.state == MemState::Free {
            continue;
        }
        match r.kind {
            MemKind::Image => {
                if let Some(m) = modules.iter().find(|m| m.contains(r.base)) {
                    let l = match m.section_at(r.base) {
                        Some(s) => format!("{} {}", m.name, s.name),
                        None if r.base == m.base => format!("{} (headers)", m.name),
                        None => m.name.clone(),
                    };
                    labels[i].push(l);
                } else if let Some(n) = mapped_cache
                    .entry(r.alloc_base)
                    .or_insert_with(|| mapped_name(r.alloc_base))
                {
                    labels[i].push(basename(n).to_string());
                }
            }
            MemKind::Mapped => {
                if let Some(n) = mapped_cache.entry(r.alloc_base).or_insert_with(|| mapped_name(r.alloc_base)) {
                    labels[i].push(format!("mapped: {}", basename(n)));
                }
            }
            _ => {}
        }
        if let Some(name) = by_alloc.get(&r.alloc_base) {
            let mut l = name.clone();
            if name.starts_with("stack") {
                let in_use = stack_ranges.iter().any(|(lo, hi, n)| n == name && r.base < *hi && r.end() > *lo);
                if r.protect.guard() {
                    l.push_str(" guard");
                } else if r.state == MemState::Reserve {
                    l.push_str(" reserve");
                } else if !in_use {
                    l.push_str(" (unused)");
                }
            }
            labels[i].push(l);
        }
    }

    let mut point = |addr: u64, label: String| {
        if let Some(i) = index_of(regions, addr) {
            if !labels[i].contains(&label) {
                labels[i].push(label);
            }
        }
    };
    if let Some(p) = extras.peb {
        point(p, "PEB".into());
    }
    if let Some(p) = extras.peb32 {
        point(p, "PEB32".into());
    }
    for t in threads.iter().filter(|t| t.teb != 0) {
        point(t.teb, format!("TEB T{}", t.tid));
    }

    for (r, l) in regions.iter_mut().zip(labels) {
        if !l.is_empty() {
            r.label = Some(l.join(", "));
        }
    }
}

fn basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Fallback when the module list is unavailable: derive modules from image allocations.
pub fn modules_from_regions(regions: &[Region], mapped_name: &dyn Fn(u64) -> Option<String>) -> Vec<Module> {
    let mut out: Vec<Module> = Vec::new();
    for r in regions.iter().filter(|r| r.kind == MemKind::Image) {
        match out.last_mut() {
            Some(m) if m.base == r.alloc_base => m.size = r.end() - m.base,
            _ => {
                let path = mapped_name(r.alloc_base).unwrap_or_default();
                out.push(Module {
                    name: basename(&path).to_string(),
                    base: r.alloc_base,
                    size: r.end() - r.alloc_base,
                    path,
                    sections: Vec::new(),
                    export_dir: None,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protect, Section, StackRange};
    use crate::regionmap::tests::region;

    #[test]
    fn labels_modules_stacks_heaps() {
        let mut img = region(0x10000, 0x1000);
        img.kind = MemKind::Image;
        let mut text = region(0x11000, 0x1000);
        text.kind = MemKind::Image;
        text.alloc_base = 0x10000;
        let mut guard = region(0x20000, 0x1000);
        guard.protect = Protect(Protect::READWRITE | Protect::GUARD);
        let mut stack = region(0x21000, 0x1000);
        stack.alloc_base = 0x20000;
        let heap = region(0x30000, 0x1000);
        let teb = region(0x40000, 0x1000);
        let mut regions = vec![img, text, guard, stack, heap, teb];
        let modules = vec![Module {
            name: "a.exe".into(),
            base: 0x10000,
            size: 0x2000,
            path: "C:\\a.exe".into(),
            sections: vec![Section { name: ".text".into(), base: 0x11000, size: 0x800, flags: "R-X".into() }],
            export_dir: None,
        }];
        let threads = vec![ThreadInfo {
            tid: 7,
            teb: 0x40010,
            stacks: vec![StackRange { base: 0x22000, limit: 0x21000, wow64: false }],
        }];
        let extras = ProcessExtras { peb: Some(0x40000), peb32: None, heaps: vec![0x30000] };
        apply(&mut regions, &modules, &threads, &extras, &|_| None);
        let l: Vec<_> = regions.iter().map(|r| r.label.clone().unwrap_or_default()).collect();
        assert_eq!(l[0], "a.exe (headers)");
        assert_eq!(l[1], "a.exe .text");
        assert_eq!(l[2], "stack T7 guard");
        assert_eq!(l[3], "stack T7");
        assert_eq!(l[4], "heap #0 (default)");
        assert_eq!(l[5], "PEB, TEB T7");
    }
}
