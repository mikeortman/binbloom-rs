//! Endianness detection.
//!
//! We don't know what a pointer looks like, so we scan the whole image and read
//! a pointer-sized value at every byte offset, once decoded as little-endian and
//! once as big-endian. Each value is masked down to its most-significant bits
//! and counted in a per-endianness [`AddrTree`].
//!
//! When the wrong endianness is assumed, the most-significant bytes vary wildly
//! and votes are spread thin; the correct endianness concentrates votes on the
//! handful of MSB prefixes that real pointers share. Whichever tree shows the
//! larger peak wins.

use crate::addrtree::{AddrTree, Node};
use crate::arch::Arch;
use crate::endianness::Endianness;
use crate::pointer::PointerReader;

/// How often (in scanned offsets) the working trees are pruned to save memory.
const CLEANUP_INTERVAL: usize = 0x10000;

/// Infers the endianness of a firmware image.
pub struct EndiannessDetector {
    arch: Arch,
    reader: PointerReader,
}

impl EndiannessDetector {
    /// Create a detector for the given architecture.
    pub fn new(arch: Arch) -> Self {
        EndiannessDetector {
            arch,
            // Endianness is supplied per read; the reader's own setting is unused.
            reader: PointerReader::new(arch, Endianness::Unknown),
        }
    }

    /// Detect the endianness of `content`. Always resolves to `Little` or `Big`
    /// (binbloom never reports "unknown" from this stage); ties favour little.
    pub fn detect(&self, content: &[u8]) -> Endianness {
        let psize = self.reader.size();
        if content.len() <= psize {
            return Endianness::Little;
        }

        let mask = Self::msb_mask(content.len());

        let mut le_tree = AddrTree::new();
        let mut be_tree = AddrTree::new();
        // Seed both trees with address 0 so the zero-prefix path always exists
        // (the 32-bit descent below relies on it).
        le_tree.register_address(0);
        be_tree.register_address(0);

        let scan_end = content.len() - psize;
        for i in 0..scan_end {
            let le = self.reader.read_as(Endianness::Little, content, i);
            let be = self.reader.read_as(Endianness::Big, content, i);

            if le != 0 && le % 4 == 0 {
                le_tree.register_address(le & mask);
            }
            if be != 0 && be % 4 == 0 {
                be_tree.register_address(be & mask);
            }

            if i % CLEANUP_INTERVAL == 0 {
                le_tree.filter(le_tree.max_vote() / 2);
                be_tree.filter(be_tree.max_vote() / 2);
            }
        }

        let max_le = self.peak_vote(&le_tree);
        let max_be = self.peak_vote(&be_tree);

        if max_be > max_le {
            Endianness::Big
        } else {
            Endianness::Little
        }
    }

    /// Mask keeping the most-significant bits above the address space implied by
    /// the file size: `~0 << (floor(log2(size)) - 1)`.
    fn msb_mask(size: usize) -> u64 {
        // Integer floor(log2(size)); the C code uses `log10/log10(2)` floats but
        // the intent is identical, and integer math avoids rounding surprises.
        let nbits = (usize::BITS - 1 - size.leading_zeros()) as i64;
        let shift = (nbits - 1).clamp(0, 63) as u32;
        u64::MAX << shift
    }

    /// Largest vote among the MSB prefixes, descending past the always-zero high
    /// bytes for 32-bit targets.
    fn peak_vote(&self, tree: &AddrTree) -> i32 {
        let node = match self.effective_root(tree.root()) {
            Some(node) => node,
            None => return 0,
        };
        let mut max = 0;
        for byte in 0..256 {
            if let Some(child) = node.child(byte) {
                let n = child.max_vote();
                if n > max {
                    max = n;
                }
            }
        }
        max
    }

    /// For 32-bit targets the significant bytes live four levels down (the top
    /// four bytes of the 64-bit slot are zero); for 64-bit it's the root itself.
    fn effective_root<'n>(&self, root: &'n Node) -> Option<&'n Node> {
        let mut node = root;
        if self.arch == Arch::Bits32 {
            for _ in 0..4 {
                node = node.child(0)?;
            }
        }
        Some(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a 32-bit firmware where many little-endian reads share the same
    /// high bytes (0x0800_xxxx) -> should be detected as little-endian.
    fn le_firmware_32() -> Vec<u8> {
        let mut data = Vec::new();
        for i in 0..2000u32 {
            // Pointers into 0x08000000..0x0800ffff, 4-aligned.
            let ptr = 0x0800_0000 + ((i * 4) & 0xffff);
            data.extend_from_slice(&ptr.to_le_bytes());
        }
        data
    }

    #[test]
    fn detects_little_endian_32() {
        let data = le_firmware_32();
        let d = EndiannessDetector::new(Arch::Bits32);
        assert_eq!(d.detect(&data), Endianness::Little);
    }

    #[test]
    fn detects_big_endian_32() {
        // Same pointers but stored big-endian -> should be detected as BE.
        let mut data = Vec::new();
        for i in 0..2000u32 {
            let ptr = 0x0800_0000 + ((i * 4) & 0xffff);
            data.extend_from_slice(&ptr.to_be_bytes());
        }
        let d = EndiannessDetector::new(Arch::Bits32);
        assert_eq!(d.detect(&data), Endianness::Big);
    }

    #[test]
    fn detects_little_endian_64() {
        let mut data = Vec::new();
        for i in 0..2000u64 {
            let ptr = 0x0000_0000_8000_0000 + ((i * 8) & 0xffff);
            data.extend_from_slice(&ptr.to_le_bytes());
        }
        let d = EndiannessDetector::new(Arch::Bits64);
        assert_eq!(d.detect(&data), Endianness::Little);
    }

    #[test]
    fn tiny_input_defaults_to_le() {
        let d = EndiannessDetector::new(Arch::Bits32);
        assert_eq!(d.detect(&[0u8; 4]), Endianness::Little);
    }

    #[test]
    fn msb_mask_is_high_bits() {
        // size 1024 -> log2 = 10 -> shift 9 -> low 9 bits cleared.
        assert_eq!(EndiannessDetector::msb_mask(1024), u64::MAX << 9);
    }
}
