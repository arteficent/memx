//! Page-granular reader with a small cache; tolerant of unreadable pages.

use std::collections::{HashMap, VecDeque};

use crate::backend::Process;
use crate::regionmap::RegionMap;

pub const PAGE: u64 = 0x1000;

#[derive(Debug, Clone)]
pub struct ReadResult {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub valid: Vec<bool>,
}

impl ReadResult {
    #[cfg(feature = "tui")]
    pub fn all_valid(&self) -> bool {
        self.valid.iter().all(|&v| v)
    }
    pub fn valid_count(&self) -> usize {
        self.valid.iter().filter(|&&v| v).count()
    }
    /// Leading run of valid bytes.
    pub fn valid_prefix(&self) -> &[u8] {
        let n = self.valid.iter().position(|&v| !v).unwrap_or(self.valid.len());
        &self.bytes[..n]
    }
}

pub struct PageCache {
    pages: HashMap<u64, Option<Vec<u8>>>,
    order: VecDeque<u64>,
    cap: usize,
}

impl PageCache {
    pub fn new(cap: usize) -> Self {
        Self { pages: HashMap::new(), order: VecDeque::new(), cap }
    }

    pub fn clear(&mut self) {
        self.pages.clear();
        self.order.clear();
    }

    fn page(&mut self, proc: &dyn Process, map: &RegionMap, page: u64) -> Option<&[u8]> {
        if !self.pages.contains_key(&page) {
            let data = if map.is_readable(page) {
                let mut buf = vec![0u8; PAGE as usize];
                let n = proc.read_raw(page, &mut buf);
                buf.truncate(n);
                (n > 0).then_some(buf)
            } else {
                None
            };
            if self.order.len() >= self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.pages.remove(&old);
                }
            }
            self.order.push_back(page);
            self.pages.insert(page, data);
        }
        self.pages.get(&page).and_then(|p| p.as_deref())
    }

    pub fn read(&mut self, proc: &dyn Process, map: &RegionMap, addr: u64, len: usize) -> ReadResult {
        let mut bytes = vec![0u8; len];
        let mut valid = vec![false; len];
        let end = addr.saturating_add(len as u64);
        let mut cur = addr;
        while cur < end {
            let page = cur & !(PAGE - 1);
            let off = (cur - page) as usize;
            let n = ((PAGE - off as u64).min(end - cur)) as usize;
            let dst = (cur - addr) as usize;
            if let Some(data) = self.page(proc, map, page) {
                let avail = data.len().saturating_sub(off).min(n);
                bytes[dst..dst + avail].copy_from_slice(&data[off..off + avail]);
                valid[dst..dst + avail].iter_mut().for_each(|v| *v = true);
            }
            cur += n as u64;
        }
        ReadResult { addr, bytes, valid }
    }
}
