use crate::model::{MemState, Region};

/// Regions sorted by base address with O(log n) lookup.
#[derive(Debug, Default, Clone)]
pub struct RegionMap {
    regions: Vec<Region>,
}

impl RegionMap {
    pub fn new(mut regions: Vec<Region>) -> Self {
        regions.sort_by_key(|r| r.base);
        Self { regions }
    }

    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    pub fn index_of(&self, addr: u64) -> Option<usize> {
        let i = self.regions.partition_point(|r| r.base <= addr);
        (i > 0 && self.regions[i - 1].contains(addr)).then(|| i - 1)
    }

    pub fn find(&self, addr: u64) -> Option<&Region> {
        self.index_of(addr).map(|i| &self.regions[i])
    }

    pub fn is_committed(&self, addr: u64) -> bool {
        self.find(addr).is_some_and(|r| r.state == MemState::Commit)
    }

    pub fn is_readable(&self, addr: u64) -> bool {
        self.find(addr).is_some_and(Region::is_readable)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{MemKind, Protect};

    pub fn region(base: u64, size: u64) -> Region {
        Region {
            base,
            size,
            state: MemState::Commit,
            protect: Protect(Protect::READWRITE),
            alloc_base: base,
            alloc_protect: Protect(Protect::READWRITE),
            kind: MemKind::Private,
            label: None,
        }
    }

    #[test]
    fn lookup() {
        let m = RegionMap::new(vec![region(0x3000, 0x1000), region(0x1000, 0x1000)]);
        assert_eq!(m.find(0x1000).unwrap().base, 0x1000);
        assert_eq!(m.find(0x1fff).unwrap().base, 0x1000);
        assert!(m.find(0x2000).is_none());
        assert_eq!(m.find(0x3800).unwrap().base, 0x3000);
        assert!(m.find(0x500).is_none());
        assert!(m.find(0x4000).is_none());
    }
}
