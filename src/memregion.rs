//! Entropy-based classification of firmware into memory regions.
//!
//! The image is sliced into fixed 1 KiB chunks; each chunk's normalised Shannon
//! entropy places it into one of three bands (uninitialised data, initialised
//! data, code). Consecutive chunks of the same kind are merged into a region.
//! Chunks whose entropy falls outside every band (>= the code maximum) are left
//! unclassified and silently skipped, exactly as in binbloom.

use crate::arch::ArchInfo;
use crate::entropy::Entropy;

/// Minimum region size / chunk granularity (1 KiB), matching the C
/// `MEMORY_REGION_MIN_SIZE`.
pub const MEMORY_REGION_MIN_SIZE: usize = 1024;

/// Kind of a memory region, ordered as in binbloom.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionType {
    Unknown,
    Code,
    InitData,
    UninitData,
}

impl ArchInfo {
    /// Classify a single chunk's entropy into a region type, or `None` when it
    /// falls outside every band.
    pub fn classify(&self, entropy: f64) -> Option<RegionType> {
        if entropy >= self.ent_uninit_data_min && entropy < self.ent_uninit_data_max {
            Some(RegionType::UninitData)
        } else if entropy >= self.ent_data_min && entropy < self.ent_data_max {
            Some(RegionType::InitData)
        } else if entropy >= self.ent_code_min && entropy < self.ent_code_max {
            Some(RegionType::Code)
        } else {
            None
        }
    }
}

/// A contiguous run of same-kind chunks.
#[derive(Clone, Copy, Debug)]
pub struct MemRegion {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub region_type: RegionType,
}

/// The classified memory map of a firmware image.
#[derive(Clone, Debug, Default)]
pub struct MemoryMap {
    regions: Vec<MemRegion>,
}

impl MemoryMap {
    /// Create an empty map.
    pub fn new() -> Self {
        MemoryMap {
            regions: Vec::new(),
        }
    }

    /// Analyse `data` into regions using the supplied entropy profile.
    pub fn analyze(data: &[u8], info: &ArchInfo) -> Self {
        let mut regions: Vec<MemRegion> = Vec::new();
        let nsections = data.len() / MEMORY_REGION_MIN_SIZE;

        let mut current: Option<(usize, usize, RegionType)> = None; // (start, size, type)

        let close = |start: usize, size: usize, ty: RegionType, regions: &mut Vec<MemRegion>| {
            let ent = Entropy::shannon(&data[start..start + size]);
            regions.push(MemRegion {
                offset: start as u64,
                size: size as u64,
                entropy: ent,
                region_type: ty,
            });
        };

        for i in 0..nsections {
            let chunk_off = i * MEMORY_REGION_MIN_SIZE;
            let chunk = &data[chunk_off..chunk_off + MEMORY_REGION_MIN_SIZE];
            let ent = Entropy::shannon(chunk);

            // An unclassified chunk neither closes nor extends the current
            // region (preserves binbloom's gap behaviour), so only act on a
            // classified one.
            if let Some(ty) = info.classify(ent) {
                match current {
                    None => current = Some((chunk_off, MEMORY_REGION_MIN_SIZE, ty)),
                    Some((start, size, prev_ty)) if prev_ty != ty => {
                        close(start, size, prev_ty, &mut regions);
                        current = Some((chunk_off, MEMORY_REGION_MIN_SIZE, ty));
                    }
                    Some((start, size, prev_ty)) => {
                        current = Some((start, size + MEMORY_REGION_MIN_SIZE, prev_ty));
                    }
                }
            }
        }

        if let Some((start, size, ty)) = current {
            close(start, size, ty, &mut regions);
        }

        MemoryMap { regions }
    }

    /// Iterate over the regions.
    pub fn iter(&self) -> std::slice::Iter<'_, MemRegion> {
        self.regions.iter()
    }

    /// Number of regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether the map has no regions.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Region type containing `offset`, or `Unknown` if none.
    pub fn get_type(&self, offset: u64) -> RegionType {
        for region in &self.regions {
            if offset >= region.offset && offset < region.offset + region.size {
                return region.region_type;
            }
        }
        RegionType::Unknown
    }

    /// Highest `offset + size` among code regions (0 if there are none).
    /// Used by the no-strings function-finding heuristic.
    pub fn max_code_addr(&self) -> u64 {
        self.regions
            .iter()
            .filter(|r| r.region_type == RegionType::Code)
            .map(|r| r.offset + r.size)
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ArchInfo {
        ArchInfo::default_profile()
    }

    /// Build a 1 KiB chunk with 128 equiprobable symbols -> entropy ~0.875,
    /// landing inside the code band [0.6, 0.9).
    fn code_chunk() -> Vec<u8> {
        (0..MEMORY_REGION_MIN_SIZE)
            .map(|i| (i % 128) as u8)
            .collect()
    }

    /// Build a 1 KiB chunk of zeros -> entropy 0 (uninitialised band).
    fn uninit_chunk() -> Vec<u8> {
        vec![0u8; MEMORY_REGION_MIN_SIZE]
    }

    /// Build a 1 KiB chunk with a handful of symbols -> low-but-nonzero entropy (data band).
    fn data_chunk() -> Vec<u8> {
        // 16 distinct symbols, equiprobable -> 4 bits/byte -> 0.5 normalised.
        (0..MEMORY_REGION_MIN_SIZE)
            .map(|i| (i % 16) as u8)
            .collect()
    }

    #[test]
    fn classify_bands() {
        let info = info();
        assert_eq!(info.classify(0.0), Some(RegionType::UninitData));
        assert_eq!(info.classify(0.04), Some(RegionType::UninitData));
        assert_eq!(info.classify(0.05), Some(RegionType::InitData));
        assert_eq!(info.classify(0.5), Some(RegionType::InitData));
        assert_eq!(info.classify(0.6), Some(RegionType::Code));
        assert_eq!(info.classify(0.85), Some(RegionType::Code));
        assert_eq!(info.classify(0.95), None);
    }

    #[test]
    fn merges_consecutive_same_type() {
        let mut data = uninit_chunk();
        data.extend(uninit_chunk());
        data.extend(code_chunk());
        let map = MemoryMap::analyze(&data, &info());
        assert_eq!(map.len(), 2);
        let regions: Vec<_> = map.iter().collect();
        assert_eq!(regions[0].region_type, RegionType::UninitData);
        assert_eq!(regions[0].size, 2 * MEMORY_REGION_MIN_SIZE as u64);
        assert_eq!(regions[1].region_type, RegionType::Code);
        assert_eq!(regions[1].offset, 2 * MEMORY_REGION_MIN_SIZE as u64);
    }

    #[test]
    fn get_type_locates_offset() {
        let mut data = data_chunk();
        data.extend(code_chunk());
        let map = MemoryMap::analyze(&data, &info());
        assert_eq!(map.get_type(0), RegionType::InitData);
        assert_eq!(
            map.get_type(MEMORY_REGION_MIN_SIZE as u64),
            RegionType::Code
        );
        assert_eq!(
            map.get_type(10 * MEMORY_REGION_MIN_SIZE as u64),
            RegionType::Unknown
        );
    }

    #[test]
    fn max_code_addr_is_region_end() {
        let mut data = data_chunk();
        data.extend(code_chunk());
        data.extend(code_chunk());
        let map = MemoryMap::analyze(&data, &info());
        assert_eq!(map.max_code_addr(), 3 * MEMORY_REGION_MIN_SIZE as u64);
    }

    #[test]
    fn trailing_partial_chunk_ignored() {
        // 1 full code chunk + a partial chunk that floor-division drops.
        let mut data = code_chunk();
        data.extend(vec![0u8; 100]);
        let map = MemoryMap::analyze(&data, &info());
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.iter().next().unwrap().size,
            MEMORY_REGION_MIN_SIZE as u64
        );
    }

    #[test]
    fn empty_when_too_small() {
        let map = MemoryMap::analyze(&[0u8; 10], &info());
        assert!(map.is_empty());
        assert_eq!(map.get_type(0), RegionType::Unknown);
    }
}
