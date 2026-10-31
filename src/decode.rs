//! Exact decoding of bytes as a user-chosen data type.

use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DataType {
    Hex,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
    Bool,
    Ptr,
    CStr,
    WStr,
    Guid,
    FileTime,
}

impl DataType {
    pub const ALL: [DataType; 17] = [
        DataType::Hex,
        DataType::U8,
        DataType::I8,
        DataType::U16,
        DataType::I16,
        DataType::U32,
        DataType::I32,
        DataType::U64,
        DataType::I64,
        DataType::F32,
        DataType::F64,
        DataType::Bool,
        DataType::Ptr,
        DataType::CStr,
        DataType::WStr,
        DataType::Guid,
        DataType::FileTime,
    ];

    pub fn name(self) -> &'static str {
        match self {
            DataType::Hex => "hex",
            DataType::U8 => "u8",
            DataType::I8 => "i8",
            DataType::U16 => "u16",
            DataType::I16 => "i16",
            DataType::U32 => "u32",
            DataType::I32 => "i32",
            DataType::U64 => "u64",
            DataType::I64 => "i64",
            DataType::F32 => "f32",
            DataType::F64 => "f64",
            DataType::Bool => "bool",
            DataType::Ptr => "ptr",
            DataType::CStr => "cstr",
            DataType::WStr => "wstr",
            DataType::Guid => "guid",
            DataType::FileTime => "filetime",
        }
    }

    /// Element size in bytes (code-unit size for strings).
    pub fn size(self, ptr_size: usize) -> usize {
        match self {
            DataType::Hex | DataType::U8 | DataType::I8 | DataType::Bool | DataType::CStr => 1,
            DataType::U16 | DataType::I16 | DataType::WStr => 2,
            DataType::U32 | DataType::I32 | DataType::F32 => 4,
            DataType::U64 | DataType::I64 | DataType::F64 | DataType::FileTime => 8,
            DataType::Ptr => ptr_size,
            DataType::Guid => 16,
        }
    }

    pub fn is_string(self) -> bool {
        matches!(self, DataType::CStr | DataType::WStr)
    }
}

impl FromStr for DataType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_ascii_lowercase();
        let t = match s.as_str() {
            "byte" | "uchar" => DataType::U8,
            "char" | "sbyte" => DataType::I8,
            "ushort" | "word" => DataType::U16,
            "short" => DataType::I16,
            "uint" | "dword" => DataType::U32,
            "int" => DataType::I32,
            "ulong" | "qword" => DataType::U64,
            "long" => DataType::I64,
            "float" => DataType::F32,
            "double" => DataType::F64,
            "pointer" | "address" => DataType::Ptr,
            "string" | "ascii" | "utf8" | "str" => DataType::CStr,
            "wstring" | "utf16" | "unicode" => DataType::WStr,
            _ => {
                return DataType::ALL
                    .into_iter()
                    .find(|t| t.name() == s)
                    .ok_or_else(|| anyhow!("unknown type '{s}' (expected one of: {})", type_list()))
            }
        };
        Ok(t)
    }
}

pub fn type_list() -> String {
    DataType::ALL.iter().map(|t| t.name()).collect::<Vec<_>>().join(", ")
}

/// A type with an optional element count, e.g. `u32[4]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeSpec {
    pub ty: DataType,
    pub count: Option<usize>,
}

impl FromStr for TypeSpec {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some(open) = s.find('[') {
            let Some(inner) = s[open + 1..].strip_suffix(']') else { bail!("malformed type '{s}'") };
            let count = inner.trim().parse::<usize>().map_err(|_| anyhow!("bad array count in '{s}'"))?;
            Ok(TypeSpec { ty: s[..open].parse()?, count: Some(count) })
        } else {
            Ok(TypeSpec { ty: s.parse()?, count: None })
        }
    }
}

pub fn read_uint(b: &[u8], n: usize) -> u64 {
    let mut a = [0u8; 8];
    a[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(a)
}

pub fn fmt_f64(v: f64) -> String {
    let a = v.abs();
    if v != 0.0 && v.is_finite() && !(1e-5..1e15).contains(&a) {
        format!("{v:e}")
    } else {
        format!("{v}")
    }
}

pub fn fmt_f32(v: f32) -> String {
    let a = v.abs();
    if v != 0.0 && v.is_finite() && !(1e-5..1e15).contains(&a) {
        format!("{v:e}")
    } else {
        format!("{v}")
    }
}

pub fn fmt_ptr(v: u64, ptr_size: usize) -> String {
    format!("0x{v:0w$x}", w = ptr_size * 2)
}

pub fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

/// Decodes a NUL-terminated string from `b` (up to `max_units` code units).
pub fn decode_string(b: &[u8], wide: bool, max_units: usize) -> String {
    let s = if wide {
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .take(max_units)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        let n = b.iter().take(max_units).position(|&c| c == 0).unwrap_or(b.len().min(max_units));
        String::from_utf8_lossy(&b[..n]).into_owned()
    };
    format!("{s:?}")
}

/// Decodes one value of type `ty` from the start of `b`. Returns `None` if `b` is too short.
pub fn decode(ty: DataType, b: &[u8], ptr_size: usize) -> Option<String> {
    let need = ty.size(ptr_size);
    if b.len() < need {
        return None;
    }
    let v = match ty {
        DataType::Hex => hex_bytes(b),
        DataType::U8 => b[0].to_string(),
        DataType::I8 => (b[0] as i8).to_string(),
        DataType::U16 => u16::from_le_bytes([b[0], b[1]]).to_string(),
        DataType::I16 => i16::from_le_bytes([b[0], b[1]]).to_string(),
        DataType::U32 => (read_uint(b, 4) as u32).to_string(),
        DataType::I32 => (read_uint(b, 4) as u32 as i32).to_string(),
        DataType::U64 => read_uint(b, 8).to_string(),
        DataType::I64 => (read_uint(b, 8) as i64).to_string(),
        DataType::F32 => fmt_f32(f32::from_bits(read_uint(b, 4) as u32)),
        DataType::F64 => fmt_f64(f64::from_bits(read_uint(b, 8))),
        DataType::Bool => match b[0] {
            0 => "false".into(),
            1 => "true".into(),
            x => format!("true (0x{x:02x})"),
        },
        DataType::Ptr => fmt_ptr(read_uint(b, ptr_size), ptr_size),
        DataType::CStr => decode_string(b, false, 4096),
        DataType::WStr => decode_string(b, true, 4096),
        DataType::Guid => {
            let d1 = read_uint(b, 4) as u32;
            let d2 = u16::from_le_bytes([b[4], b[5]]);
            let d3 = u16::from_le_bytes([b[6], b[7]]);
            format!(
                "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{}}}",
                b[8],
                b[9],
                b[10..16].iter().map(|x| format!("{x:02X}")).collect::<String>()
            )
        }
        DataType::FileTime => fmt_filetime(read_uint(b, 8)),
    };
    Some(v)
}

/// Decodes `count` consecutive values (or a single string) from `b`.
pub fn decode_spec(spec: TypeSpec, b: &[u8], ptr_size: usize) -> Vec<(usize, String)> {
    if spec.ty.is_string() {
        let wide = spec.ty == DataType::WStr;
        let max = spec.count.unwrap_or(4096);
        return vec![(0, decode_string(b, wide, max))];
    }
    let sz = spec.ty.size(ptr_size);
    let count = spec.count.unwrap_or(if spec.ty == DataType::Hex { b.len() } else { b.len() / sz.max(1) });
    (0..count)
        .map(|i| i * sz)
        .take_while(|&off| off + sz <= b.len())
        .filter_map(|off| decode(spec.ty, &b[off..], ptr_size).map(|v| (off, v)))
        .collect()
}

/// FILETIME (100ns ticks since 1601-01-01 UTC) as an ISO-like timestamp.
pub fn fmt_filetime(ticks: u64) -> String {
    if ticks == 0 {
        return "0".into();
    }
    let secs = (ticks / 10_000_000) as i64 - 11_644_473_600;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if !(1601..=9999).contains(&y) {
        return format!("invalid ({ticks})");
    }
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, (rem / 60) % 60, rem % 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::approx_constant)]
    fn ints_and_floats() {
        let b = 0xDEADBEEFu32.to_le_bytes();
        assert_eq!(decode(DataType::U32, &b, 8).unwrap(), "3735928559");
        assert_eq!(decode(DataType::I32, &b, 8).unwrap(), "-559038737");
        assert_eq!(decode(DataType::F64, &3.14159f64.to_le_bytes(), 8).unwrap(), "3.14159");
        assert_eq!(decode(DataType::F32, &1.5f32.to_le_bytes(), 8).unwrap(), "1.5");
        assert!(decode(DataType::U64, &b, 8).is_none());
    }

    #[test]
    fn pointers_follow_target_width() {
        let b = 0x1234u64.to_le_bytes();
        assert_eq!(decode(DataType::Ptr, &b, 4).unwrap(), "0x00001234");
        assert_eq!(decode(DataType::Ptr, &b, 8).unwrap(), "0x0000000000001234");
    }

    #[test]
    fn strings() {
        assert_eq!(decode(DataType::CStr, b"hi\0junk", 8).unwrap(), "\"hi\"");
        let w: Vec<u8> = "héllo\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode(DataType::WStr, &w, 8).unwrap(), "\"héllo\"");
        // Unterminated and invalid input must not panic.
        assert_eq!(decode(DataType::CStr, &[0xff, 0xfe], 8).unwrap(), "\"\u{fffd}\u{fffd}\"");
        assert_eq!(decode(DataType::WStr, &[0x41], 8), None);
    }

    #[test]
    fn guid_and_filetime() {
        let g = [0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(decode(DataType::Guid, &g, 8).unwrap(), "{12345678-1234-5678-0102-030405060708}");
        // 2000-01-01 00:00:00 UTC
        assert_eq!(fmt_filetime(125_911_584_000_000_000), "2000-01-01 00:00:00 UTC");
    }

    #[test]
    fn specs() {
        let s: TypeSpec = "u16[3]".parse().unwrap();
        assert_eq!(s, TypeSpec { ty: DataType::U16, count: Some(3) });
        let vals = decode_spec(s, &[1, 0, 2, 0, 3, 0, 4, 0], 8);
        assert_eq!(vals, vec![(0, "1".into()), (2, "2".into()), (4, "3".into())]);
        assert!("nope".parse::<TypeSpec>().is_err());
        assert_eq!("double".parse::<DataType>().unwrap(), DataType::F64);
    }
}
