use std::io::{self, Write};

use serde::Serialize;

use crate::infer::Annotation;
use crate::reader::ReadResult;

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

pub fn addr(v: u64, ptr_size: usize) -> String {
    format!("{v:0w$x}", w = ptr_size * 2)
}

/// Left-aligned text table; the last column is not padded.
pub fn table(out: &mut dyn Write, headers: &[&str], rows: &[Vec<String>]) -> io::Result<()> {
    let mut w: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| -> String {
        let last = cells.len() - 1;
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| if i == last { c.to_string() } else { format!("{c:<width$}", width = w[i]) })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    writeln!(out, "{}", line(headers.to_vec()))?;
    let dashes: Vec<String> = w.iter().map(|&n| "-".repeat(n)).collect();
    writeln!(out, "{}", line(dashes.iter().map(String::as_str).collect()))?;
    for r in rows {
        writeln!(out, "{}", line(r.iter().map(String::as_str).collect()))?;
    }
    Ok(())
}

pub fn hexdump_lines(r: &ReadResult, ptr_size: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut off = 0;
    while off < r.bytes.len() {
        let end = (off + 16).min(r.bytes.len());
        let mut hex = String::with_capacity(52);
        let mut ascii = String::with_capacity(16);
        for i in off..off + 16 {
            if i == off + 8 {
                hex.push(' ');
            }
            if i < end && r.valid[i] {
                hex.push_str(&format!("{:02x} ", r.bytes[i]));
                let c = r.bytes[i];
                ascii.push(if (0x20..0x7f).contains(&c) { c as char } else { '.' });
            } else if i < end {
                hex.push_str("?? ");
                ascii.push(' ');
            } else {
                hex.push_str("   ");
            }
        }
        lines.push(format!("{}  {hex} |{ascii}|", addr(r.addr + off as u64, ptr_size)));
        off = end;
    }
    lines
}

pub fn hexdump(out: &mut dyn Write, r: &ReadResult, ptr_size: usize) -> io::Result<()> {
    for l in hexdump_lines(r, ptr_size) {
        writeln!(out, "{l}")?;
    }
    Ok(())
}

pub fn raw_hex(r: &ReadResult, a: &Annotation) -> String {
    let s = (a.addr - r.addr) as usize;
    let e = (s + a.len.min(8)).min(r.bytes.len());
    let mut h: Vec<String> = (s..e)
        .map(|i| if r.valid[i] { format!("{:02x}", r.bytes[i]) } else { "??".into() })
        .collect();
    if a.len > 8 {
        h.push("..".into());
    }
    h.join(" ")
}

pub fn annotation_rows(r: &ReadResult, anns: &[Annotation], ptr_size: usize) -> Vec<Vec<String>> {
    anns.iter()
        .map(|a| {
            let ty = match &a.field {
                Some(f) => format!("{f}: {}", a.ty),
                None => a.ty.clone(),
            };
            vec![
                addr(a.addr, ptr_size),
                a.len.to_string(),
                raw_hex(r, a),
                ty,
                format!("{:?}", a.confidence).to_lowercase(),
                format!("{:?}", a.source).to_lowercase(),
                a.value.clone(),
            ]
        })
        .collect()
}

pub fn annotations(out: &mut dyn Write, r: &ReadResult, anns: &[Annotation], ptr_size: usize) -> io::Result<()> {
    table(
        out,
        &["Address", "Len", "Raw", "Type", "Conf", "Source", "Value"],
        &annotation_rows(r, anns, ptr_size),
    )
}

pub fn json<T: Serialize + ?Sized>(out: &mut dyn Write, v: &T) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, v)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(4096), "4.0 KiB");
        assert_eq!(human_size(3 << 20), "3.0 MiB");
    }

    #[test]
    fn hexdump_marks_unreadable() {
        let r = ReadResult { addr: 0x10, bytes: b"AB".to_vec(), valid: vec![true, false] };
        let l = hexdump_lines(&r, 4);
        assert!(l[0].starts_with("00000010  41 ?? "), "{}", l[0]);
        assert!(l[0].ends_with("|A |"), "{}", l[0]);
    }
}
