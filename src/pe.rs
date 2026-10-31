//! Minimal PE parsing (sections, export table) over remote memory.

use crate::model::Section;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

pub struct PeHeaders {
    pub sections: Vec<Section>,
    pub export_dir: Option<(u32, u32)>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Parses headers from the first page of a mapped image at `base`.
pub fn parse_headers(base: u64, hdr: &[u8]) -> Option<PeHeaders> {
    if hdr.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(hdr, 0x3C)? as usize;
    if hdr.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let fh = pe + 4;
    let nsec = u16_at(hdr, fh + 2)? as usize;
    let opt_size = u16_at(hdr, fh + 16)? as usize;
    let opt = fh + 20;
    let magic = u16_at(hdr, opt)?;
    let dirs = match magic {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    let export_dir = match (u32_at(hdr, dirs), u32_at(hdr, dirs + 4)) {
        (Some(rva), Some(size)) if rva != 0 && size != 0 => Some((rva, size)),
        _ => None,
    };
    let mut sections = Vec::with_capacity(nsec);
    let mut s = opt + opt_size;
    for _ in 0..nsec.min(96) {
        let Some(raw_name) = hdr.get(s..s + 8) else { break };
        let n = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..n]).into_owned();
        let vsize = u32_at(hdr, s + 8)?;
        let rva = u32_at(hdr, s + 12)?;
        let ch = u32_at(hdr, s + 36)?;
        let flags = format!(
            "{}{}{}",
            if ch & SCN_MEM_READ != 0 { 'R' } else { '-' },
            if ch & SCN_MEM_WRITE != 0 { 'W' } else { '-' },
            if ch & SCN_MEM_EXECUTE != 0 { 'X' } else { '-' }
        );
        sections.push(Section { name, base: base + rva as u64, size: vsize as u64, flags });
        s += 40;
    }
    Some(PeHeaders { sections, export_dir })
}

/// Reads the export table; returns `(address, name)` pairs, skipping forwarders.
pub fn parse_exports(
    base: u64,
    dir: (u32, u32),
    read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Vec<(u64, String)> {
    let (dir_rva, dir_size) = dir;
    let dir_size = dir_size.min(16 << 20);
    let Some(block) = read(base + dir_rva as u64, dir_size as usize) else { return Vec::new() };
    let mut get = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let start = rva.checked_sub(dir_rva)? as usize;
        match block.get(start..start + len) {
            Some(s) => Some(s.to_vec()),
            None => read(base + rva as u64, len),
        }
    };
    let Some(d) = get(dir_rva, 40) else { return Vec::new() };
    let (Some(nfuncs), Some(nnames), Some(funcs), Some(names), Some(ords)) =
        (u32_at(&d, 0x14), u32_at(&d, 0x18), u32_at(&d, 0x1C), u32_at(&d, 0x20), u32_at(&d, 0x24))
    else {
        return Vec::new();
    };
    let nfuncs = nfuncs.min(65_536) as usize;
    let nnames = nnames.min(65_536) as usize;
    let (Some(fbuf), Some(nbuf), Some(obuf)) = (get(funcs, nfuncs * 4), get(names, nnames * 4), get(ords, nnames * 2))
    else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(nnames);
    for i in 0..nnames {
        let (Some(name_rva), Some(ord)) = (u32_at(&nbuf, i * 4), u16_at(&obuf, i * 2)) else { continue };
        let Some(func_rva) = u32_at(&fbuf, ord as usize * 4) else { continue };
        if func_rva >= dir_rva && func_rva < dir_rva + dir_size {
            continue;
        }
        let Some(raw) = get(name_rva, 256).or_else(|| get(name_rva, 64)) else { continue };
        let n = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        out.push((base + func_rva as u64, String::from_utf8_lossy(&raw[..n]).into_owned()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_image() -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        let fh = 0x84;
        img[fh + 2..fh + 4].copy_from_slice(&1u16.to_le_bytes());
        img[fh + 16..fh + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = fh + 20;
        img[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        img[opt + 112..opt + 116].copy_from_slice(&0x200u32.to_le_bytes());
        img[opt + 116..opt + 120].copy_from_slice(&0x100u32.to_le_bytes());
        let s = opt + 0xF0;
        img[s..s + 5].copy_from_slice(b".text");
        img[s + 8..s + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        img[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        img[s + 36..s + 40].copy_from_slice(&(SCN_MEM_READ | SCN_MEM_EXECUTE).to_le_bytes());
        // Export directory at 0x200: 1 function, 1 name.
        let e = 0x200;
        img[e + 0x14..e + 0x18].copy_from_slice(&1u32.to_le_bytes());
        img[e + 0x18..e + 0x1C].copy_from_slice(&1u32.to_le_bytes());
        img[e + 0x1C..e + 0x20].copy_from_slice(&0x240u32.to_le_bytes());
        img[e + 0x20..e + 0x24].copy_from_slice(&0x250u32.to_le_bytes());
        img[e + 0x24..e + 0x28].copy_from_slice(&0x260u32.to_le_bytes());
        img[0x240..0x244].copy_from_slice(&0x1010u32.to_le_bytes());
        img[0x250..0x254].copy_from_slice(&0x270u32.to_le_bytes());
        img[0x270..0x277].copy_from_slice(b"DoWork\0");
        img
    }

    #[test]
    fn headers_and_exports() {
        let img = fake_image();
        let base = 0x1_4000_0000;
        let h = parse_headers(base, &img).unwrap();
        assert_eq!(h.sections.len(), 1);
        assert_eq!(h.sections[0].name, ".text");
        assert_eq!(h.sections[0].base, base + 0x1000);
        assert_eq!(h.sections[0].flags, "R-X");
        assert_eq!(h.export_dir, Some((0x200, 0x100)));
        let mut read = |a: u64, n: usize| {
            let o = (a - base) as usize;
            img.get(o..o + n).map(|s| s.to_vec())
        };
        let ex = parse_exports(base, h.export_dir.unwrap(), &mut read);
        assert_eq!(ex, vec![(base + 0x1010, "DoWork".to_string())]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_headers(0, &[0u8; 64]).is_none());
        assert!(parse_headers(0, b"MZ").is_none());
    }
}
