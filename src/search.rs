//! Pattern search across readable memory.

use anyhow::{bail, Result};

use crate::backend::Process;
use crate::regionmap::RegionMap;

const CHUNK: usize = 1 << 20;

/// Parses `"de ad ?? ef"` into bytes with `None` wildcards.
pub fn parse_hex_pattern(s: &str) -> Result<Vec<Option<u8>>> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        bail!("hex pattern must contain an even number of digits");
    }
    compact
        .as_bytes()
        .chunks(2)
        .map(|c| {
            let t = std::str::from_utf8(c).unwrap();
            if t == "??" {
                Ok(None)
            } else {
                u8::from_str_radix(t, 16).map(Some).map_err(|_| anyhow::anyhow!("bad hex byte '{t}'"))
            }
        })
        .collect()
}

fn matches_at(hay: &[u8], pat: &[Option<u8>]) -> bool {
    hay.len() >= pat.len() && pat.iter().zip(hay).all(|(p, h)| p.is_none_or(|p| p == *h))
}

fn scan(hay: &[u8], base: u64, pat: &[Option<u8>], align: u64, out: &mut Vec<u64>, max: usize) {
    if hay.len() < pat.len() {
        return;
    }
    let last = hay.len() - pat.len();
    let mut i = 0;
    while i <= last && out.len() < max {
        if let Some(first) = pat[0] {
            match hay[i..=last].iter().position(|&b| b == first) {
                Some(p) => i += p,
                None => break,
            }
        }
        let a = base + i as u64;
        if a.is_multiple_of(align) && matches_at(&hay[i..], pat) {
            out.push(a);
        }
        i += 1;
    }
}

/// Returns up to `max` addresses `>= start` where `pat` occurs.
pub fn search(proc: &dyn Process, map: &RegionMap, pat: &[Option<u8>], align: usize, start: u64, max: usize) -> Vec<u64> {
    let mut out = Vec::new();
    if pat.is_empty() {
        return out;
    }
    let align = align.max(1) as u64;
    let overlap = pat.len() - 1;
    for r in map.regions().iter().filter(|r| r.is_readable() && r.end() > start) {
        let mut cur = r.base.max(start);
        while cur < r.end() && out.len() < max {
            let len = ((r.end() - cur) as usize).min(CHUNK + overlap);
            let mut buf = vec![0u8; len];
            let n = proc.read_raw(cur, &mut buf);
            if n == 0 {
                cur = (cur & !0xFFF) + 0x1000;
                continue;
            }
            scan(&buf[..n], cur, pat, align, &mut out, max);
            let step = if n == len { len.saturating_sub(overlap).max(1) } else { n.max(1) };
            cur += step as u64;
        }
        if out.len() >= max {
            break;
        }
    }
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(parse_hex_pattern("de ad ?? ef").unwrap(), vec![Some(0xde), Some(0xad), None, Some(0xef)]);
        assert!(parse_hex_pattern("abc").is_err());
        let mut out = Vec::new();
        scan(b"xxabcxabc", 0x100, &[Some(b'a'), None, Some(b'c')], 1, &mut out, 10);
        assert_eq!(out, vec![0x102, 0x106]);
        out.clear();
        scan(b"xxabcxabc", 0x100, &[Some(b'a')], 4, &mut out, 10);
        assert!(out.is_empty());
    }
}
