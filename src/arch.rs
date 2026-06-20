//! Target architecture (pointer width) and the entropy profile used to
//! classify memory regions.

use crate::error::{BinbloomError, Result};

/// Pointer width of the analysed firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Arch {
    /// 32-bit architecture (4-byte pointers). This is binbloom's default.
    #[default]
    Bits32,
    /// 64-bit architecture (8-byte pointers).
    Bits64,
}

impl Arch {
    /// Pointer size in bytes for this architecture.
    pub fn pointer_size(self) -> usize {
        match self {
            Arch::Bits32 => 4,
            Arch::Bits64 => 8,
        }
    }

    /// Largest representable pointer value for this architecture.
    pub fn max_value(self) -> u64 {
        match self {
            Arch::Bits32 => 0xffff_ffff,
            Arch::Bits64 => 0xffff_ffff_ffff_ffff,
        }
    }

    /// Parse an architecture from the textual CLI argument (`"32"` / `"64"`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "32" => Ok(Arch::Bits32),
            "64" => Ok(Arch::Bits64),
            other => Err(BinbloomError::InvalidArch(other.to_string())),
        }
    }
}

/// Entropy thresholds used to classify a memory region as uninitialised data,
/// initialised data or code.
///
/// The original binbloom keeps a table of these profiles keyed by name but only
/// ever ships a single `"default"` profile; we expose the same lookup while
/// fixing the C version's infinite loop on an unknown name.
#[derive(Clone, Copy, Debug)]
pub struct ArchInfo {
    pub name: &'static str,
    pub arch: Arch,
    pub ent_uninit_data_min: f64,
    pub ent_uninit_data_max: f64,
    pub ent_data_min: f64,
    pub ent_data_max: f64,
    pub ent_code_min: f64,
    pub ent_code_max: f64,
}

impl ArchInfo {
    /// The single built-in profile shipped by binbloom.
    pub const fn default_profile() -> Self {
        ArchInfo {
            name: "default",
            arch: Arch::Bits32,
            ent_uninit_data_min: 0.0,
            ent_uninit_data_max: 0.05,
            ent_data_min: 0.05,
            ent_data_max: 0.6,
            ent_code_min: 0.6,
            ent_code_max: 0.9,
        }
    }

    /// Look up a profile by name, returning `None` if it is unknown.
    pub fn get(name: &str) -> Option<Self> {
        let default = Self::default_profile();
        if name == default.name {
            Some(default)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_sizes() {
        assert_eq!(Arch::Bits32.pointer_size(), 4);
        assert_eq!(Arch::Bits64.pointer_size(), 8);
    }

    #[test]
    fn max_values() {
        assert_eq!(Arch::Bits32.max_value(), 0xffff_ffff);
        assert_eq!(Arch::Bits64.max_value(), u64::MAX);
    }

    #[test]
    fn parse_valid_and_invalid() {
        assert_eq!(Arch::parse("32").unwrap(), Arch::Bits32);
        assert_eq!(Arch::parse("64").unwrap(), Arch::Bits64);
        assert!(matches!(
            Arch::parse("128"),
            Err(BinbloomError::InvalidArch(_))
        ));
    }

    #[test]
    fn default_is_32bit() {
        assert_eq!(Arch::default(), Arch::Bits32);
    }

    #[test]
    fn arch_info_lookup() {
        let info = ArchInfo::get("default").unwrap();
        assert_eq!(info.ent_code_min, 0.6);
        assert_eq!(info.ent_code_max, 0.9);
        // Unknown names must not hang (the C version loops forever here).
        assert!(ArchInfo::get("nonexistent").is_none());
    }
}
