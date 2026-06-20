//! Decoding pointer-sized values from firmware bytes.
//!
//! Mirrors binbloom's `read_pointer` / `is_ascii_ptr` helpers. Reads are
//! bounds-checked and zero-padded when they would run past the end of the
//! buffer; the original C code relies on the calling loops to stay in bounds
//! and would otherwise over-read, which we avoid while keeping identical
//! results for every in-bounds access.

use crate::arch::Arch;
use crate::endianness::Endianness;

/// Reads pointer-sized values from a byte buffer for a fixed architecture and
/// (default) endianness.
#[derive(Clone, Copy, Debug)]
pub struct PointerReader {
    arch: Arch,
    endian: Endianness,
}

impl PointerReader {
    /// Create a reader for the given architecture and endianness.
    pub fn new(arch: Arch, endian: Endianness) -> Self {
        PointerReader { arch, endian }
    }

    /// Pointer size in bytes.
    pub fn size(&self) -> usize {
        self.arch.pointer_size()
    }

    /// Target architecture.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Read a pointer at `offset` using the reader's configured endianness.
    ///
    /// `Endianness::Unknown` is treated as little-endian, matching the C code
    /// which decodes natively (x86, little-endian) when no swap is requested.
    pub fn read(&self, content: &[u8], offset: usize) -> u64 {
        self.read_as(self.endian, content, offset)
    }

    /// Read a pointer at `offset` interpreting bytes with `endian`.
    pub fn read_as(&self, endian: Endianness, content: &[u8], offset: usize) -> u64 {
        match self.arch {
            Arch::Bits32 => {
                let bytes = Self::four_bytes(content, offset);
                match endian {
                    Endianness::Big => u32::from_be_bytes(bytes) as u64,
                    _ => u32::from_le_bytes(bytes) as u64,
                }
            }
            Arch::Bits64 => {
                let bytes = Self::eight_bytes(content, offset);
                match endian {
                    Endianness::Big => u64::from_be_bytes(bytes),
                    _ => u64::from_le_bytes(bytes),
                }
            }
        }
    }

    /// Returns `true` when every byte of `value` (over the pointer width) is a
    /// printable ASCII character, i.e. the value most likely holds text rather
    /// than a real pointer.
    pub fn is_ascii_ptr(&self, value: u64) -> bool {
        let mut v = value;
        for _ in 0..self.size() {
            let byte = (v & 0xff) as u8;
            if !(0x20..=0x7f).contains(&byte) {
                return false;
            }
            v >>= 8;
        }
        true
    }

    fn four_bytes(content: &[u8], offset: usize) -> [u8; 4] {
        let mut buf = [0u8; 4];
        for (i, slot) in buf.iter_mut().enumerate() {
            if let Some(&b) = content.get(offset + i) {
                *slot = b;
            }
        }
        buf
    }

    fn eight_bytes(content: &[u8], offset: usize) -> [u8; 8] {
        let mut buf = [0u8; 8];
        for (i, slot) in buf.iter_mut().enumerate() {
            if let Some(&b) = content.get(offset + i) {
                *slot = b;
            }
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: [u8; 8] = [0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x90];

    #[test]
    fn read_32_le() {
        let r = PointerReader::new(Arch::Bits32, Endianness::Little);
        assert_eq!(r.read(&DATA, 0), 0x1234_5678);
    }

    #[test]
    fn read_32_be() {
        let r = PointerReader::new(Arch::Bits32, Endianness::Big);
        assert_eq!(r.read(&DATA, 0), 0x7856_3412);
    }

    #[test]
    fn read_64_le() {
        let r = PointerReader::new(Arch::Bits64, Endianness::Little);
        assert_eq!(r.read(&DATA, 0), 0x90ab_cdef_1234_5678);
    }

    #[test]
    fn read_64_be() {
        let r = PointerReader::new(Arch::Bits64, Endianness::Big);
        assert_eq!(r.read(&DATA, 0), 0x7856_3412_efcd_ab90);
    }

    #[test]
    fn unknown_endian_reads_as_le() {
        let r = PointerReader::new(Arch::Bits32, Endianness::Unknown);
        assert_eq!(r.read(&DATA, 0), 0x1234_5678);
    }

    #[test]
    fn read_as_overrides_default() {
        let r = PointerReader::new(Arch::Bits32, Endianness::Little);
        assert_eq!(r.read_as(Endianness::Big, &DATA, 0), 0x7856_3412);
    }

    #[test]
    fn out_of_bounds_is_zero_padded() {
        let r = PointerReader::new(Arch::Bits32, Endianness::Little);
        // Only one byte available -> the rest are treated as zero.
        assert_eq!(r.read(&[0xaa], 0), 0x0000_00aa);
        // Entirely past the end -> zero.
        assert_eq!(r.read(&DATA, 100), 0);
    }

    #[test]
    fn ascii_detection_32() {
        let r = PointerReader::new(Arch::Bits32, Endianness::Little);
        // "ABCD" -> all printable.
        assert!(r.is_ascii_ptr(0x4443_4241));
        // contains 0x00 -> not all printable.
        assert!(!r.is_ascii_ptr(0x4443_4200));
        // contains 0xff -> not printable.
        assert!(!r.is_ascii_ptr(0xff43_4241));
    }

    #[test]
    fn ascii_detection_64_ignores_high_bytes_for_32() {
        // For a 32-bit reader only the low 4 bytes matter.
        let r = PointerReader::new(Arch::Bits32, Endianness::Little);
        assert!(r.is_ascii_ptr(0xffff_ffff_4443_4241));
    }
}
