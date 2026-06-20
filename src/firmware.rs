//! High-level entry point tying the analysis engines together.

use crate::arch::{Arch, ArchInfo};
use crate::base_address::{BaseAddressFinder, BaseAddressResult};
use crate::endian_detect::EndiannessDetector;
use crate::endianness::Endianness;
use crate::error::{BinbloomError, Result};
use crate::log::Logger;
use crate::memregion::MemoryMap;
use crate::poi::PoiList;
use crate::uds::{UdsFinder, UdsResult};
use std::path::Path;

/// Result of a base-address analysis, including the endianness used.
#[derive(Clone, Debug)]
pub struct BaseAddressAnalysis {
    pub endianness: Endianness,
    pub result: BaseAddressResult,
}

/// A firmware image plus the configuration needed to analyse it.
#[derive(Clone, Debug)]
pub struct Firmware {
    content: Vec<u8>,
    arch: Arch,
    endian: Endianness,
    alignment: u64,
    deep: bool,
    nb_threads: usize,
    ptr_aligned: bool,
    logger: Logger,
}

impl Firmware {
    /// Default base-address alignment, matching binbloom (`0x1000`).
    pub const DEFAULT_ALIGNMENT: u64 = 0x1000;

    /// Build a firmware from raw bytes for the given architecture, with default
    /// settings (auto endianness, single thread, 0x1000 alignment).
    pub fn from_bytes(content: Vec<u8>, arch: Arch) -> Result<Self> {
        let required = arch.pointer_size();
        if content.len() < required {
            return Err(BinbloomError::FileTooSmall {
                required,
                actual: content.len(),
            });
        }
        Ok(Firmware {
            content,
            arch,
            endian: Endianness::Unknown,
            alignment: Self::DEFAULT_ALIGNMENT,
            deep: false,
            nb_threads: 1,
            ptr_aligned: false,
            logger: Logger::default(),
        })
    }

    /// Read a firmware file from `path` for the given architecture.
    pub fn read(path: impl AsRef<Path>, arch: Arch) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read(path).map_err(|source| BinbloomError::FileAccess {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_bytes(content, arch)
    }

    /// Build a firmware by draining an arbitrary byte stream (stdin, a pipe, a
    /// socket, a decompressor, ...) into memory.
    ///
    /// binbloom's heuristics make many random-access passes over the whole
    /// image, so the full content must be resident: this reads the stream to
    /// its end rather than processing it incrementally.
    pub fn from_reader<R: std::io::Read>(mut reader: R, arch: Arch) -> Result<Self> {
        let mut content = Vec::new();
        reader.read_to_end(&mut content)?;
        Self::from_bytes(content, arch)
    }

    /// Force a specific endianness instead of auto-detecting.
    pub fn with_endianness(mut self, endian: Endianness) -> Self {
        self.endian = endian;
        self
    }

    /// Set the candidate base-address alignment.
    pub fn with_alignment(mut self, alignment: u64) -> Self {
        self.alignment = alignment;
        self
    }

    /// Enable deep search (refine every candidate).
    pub fn with_deep(mut self, deep: bool) -> Self {
        self.deep = deep;
        self
    }

    /// Set the number of refinement threads.
    pub fn with_threads(mut self, nb_threads: usize) -> Self {
        self.nb_threads = nb_threads.max(1);
        self
    }

    /// Enable the optional pointer-alignment heuristic (the `-l` flag).
    pub fn with_pointer_alignment(mut self, ptr_aligned: bool) -> Self {
        self.ptr_aligned = ptr_aligned;
        self
    }

    /// Attach a logger.
    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = logger;
        self
    }

    /// Image size in bytes.
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Whether the image is empty.
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Raw firmware bytes.
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// The architecture this firmware is analysed as.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Classify the image into entropy-based memory regions.
    pub fn memory_map(&self) -> MemoryMap {
        MemoryMap::analyze(&self.content, &ArchInfo::default_profile())
    }

    /// Resolve the endianness to use: the forced value, or the detected one.
    pub fn resolve_endianness(&self) -> Endianness {
        if self.endian != Endianness::Unknown {
            self.endian
        } else {
            EndiannessDetector::new(self.arch).detect(&self.content)
        }
    }

    /// Recover the base address, optionally seeded with a known-symbols list.
    pub fn find_base_address(&self, symbols: Option<&PoiList>) -> Result<BaseAddressAnalysis> {
        let memory = self.memory_map();
        let endian = self.resolve_endianness();
        self.logger
            .message(&format!("[i] Endianness is {}", endian.label()));

        let result = if let Some(symbols) = symbols {
            // Seed from the symbol list, then add strings/value arrays into it.
            let mut poi_list = symbols.clone();
            let seeder = self.make_finder(endian, &memory, None);
            seeder.populate_poi(&mut poi_list, true);
            let finder = self.make_finder(endian, &memory, Some(&poi_list));
            finder.compute_candidates(&poi_list)?
        } else {
            let finder = self.make_finder(endian, &memory, None);
            let mut poi_list = finder.index_poi(true);
            finder.index_functions(&mut poi_list);
            finder.compute_candidates(&poi_list)?
        };

        Ok(BaseAddressAnalysis {
            endianness: endian,
            result,
        })
    }

    /// Search for a UDS database given a known base address, optionally seeded
    /// with a known-symbols list (the `-f` functions file).
    pub fn find_uds(&self, base: u64, symbols: Option<&PoiList>) -> Option<UdsResult> {
        let memory = self.memory_map();
        let endian = self.resolve_endianness();
        UdsFinder::new(
            &self.content,
            self.arch,
            endian,
            &memory,
            self.logger,
            symbols,
        )
        .find(base)
    }

    fn make_finder<'a>(
        &'a self,
        endian: Endianness,
        memory: &'a MemoryMap,
        symbols: Option<&'a PoiList>,
    ) -> BaseAddressFinder<'a> {
        BaseAddressFinder::new(
            &self.content,
            self.arch,
            endian,
            memory,
            self.alignment,
            self.deep,
            self.nb_threads,
            self.ptr_aligned,
            symbols,
            self.logger,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_small_file_rejected() {
        let err = Firmware::from_bytes(vec![0u8; 3], Arch::Bits32);
        assert!(matches!(err, Err(BinbloomError::FileTooSmall { .. })));
    }

    #[test]
    fn from_reader_drains_stream() {
        let bytes = vec![0xaau8; 64];
        let cursor = std::io::Cursor::new(bytes.clone());
        let fw = Firmware::from_reader(cursor, Arch::Bits32).unwrap();
        assert_eq!(fw.content(), bytes.as_slice());
    }

    #[test]
    fn from_reader_rejects_short_stream() {
        let cursor = std::io::Cursor::new(vec![0u8; 2]);
        assert!(matches!(
            Firmware::from_reader(cursor, Arch::Bits32),
            Err(BinbloomError::FileTooSmall { .. })
        ));
    }

    #[test]
    fn forced_endianness_used() {
        let fw = Firmware::from_bytes(vec![0u8; 64], Arch::Bits32)
            .unwrap()
            .with_endianness(Endianness::Big);
        assert_eq!(fw.resolve_endianness(), Endianness::Big);
    }
}
