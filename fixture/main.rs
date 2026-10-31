//! Test target: places known values at known addresses, prints them as JSON, then waits for stdin.
// 3.14159 / 2.71828 are deliberate, recognizable test values.
#![allow(clippy::approx_constant)]

use std::io::{self, BufRead, Write};
use std::ptr::{addr_of, addr_of_mut};

#[repr(C)]
pub struct FixtureData {
    pub magic: u64,
    pub count: i64,
    pub pi: f64,
    pub ratios: [f32; 2],
    pub name: [u8; 16],
    pub wname: [u16; 16],
    pub next: *const FixtureData,
}

const fn wide16(s: &[u8]) -> [u16; 16] {
    let mut out = [0u16; 16];
    let mut i = 0;
    while i < s.len() && i < 15 {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

const fn narrow16(s: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < s.len() && i < 15 {
        out[i] = s[i];
        i += 1;
    }
    out
}

#[no_mangle]
pub static mut FIXTURE_GLOBAL: FixtureData = FixtureData {
    magic: 0xDEADBEEF,
    count: -42,
    pi: 3.14159,
    ratios: [1.25, 0.5],
    name: narrow16(b"fixture-global"),
    wname: wide16(b"wide-global"),
    next: std::ptr::null(),
};

fn main() {
    let global = addr_of_mut!(FIXTURE_GLOBAL);
    let heap = Box::new(FixtureData {
        magic: 0xCAFEBABE,
        count: 7,
        pi: 2.71828,
        ratios: [0.75, 4.0],
        name: narrow16(b"fixture-heap"),
        wname: wide16(b"wide-heap"),
        next: global,
    });
    let heap_ptr: *const FixtureData = &*heap;
    unsafe { (*global).next = heap_ptr };

    let a = |p: *const u8| format!("\"0x{:x}\"", p as usize);
    let g = global as *const FixtureData;
    let line = unsafe {
        format!(
            "{{\"pid\":{},\"global\":{},\"heap\":{},\"magic\":{},\"count\":{},\"pi\":{},\"ratios\":{},\"name\":{},\"wname\":{},\"next\":{},\"heap_name\":{},\"heap_next\":{}}}",
            std::process::id(),
            a(g as *const u8),
            a(heap_ptr as *const u8),
            a(addr_of!((*g).magic) as *const u8),
            a(addr_of!((*g).count) as *const u8),
            a(addr_of!((*g).pi) as *const u8),
            a(addr_of!((*g).ratios) as *const u8),
            a(addr_of!((*g).name) as *const u8),
            a(addr_of!((*g).wname) as *const u8),
            a(addr_of!((*g).next) as *const u8),
            a(addr_of!((*heap_ptr).name) as *const u8),
            a(addr_of!((*heap_ptr).next) as *const u8),
        )
    };
    let mut out = io::stdout().lock();
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();
    drop(out);

    let mut s = String::new();
    let _ = io::stdin().lock().read_line(&mut s);
    std::hint::black_box(&heap);
    std::hint::black_box(addr_of!(FIXTURE_GLOBAL));
}
