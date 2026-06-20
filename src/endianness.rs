//! Endianness of the analysed firmware.

use crate::error::{BinbloomError, Result};

/// Byte order used to decode multi-byte values from the firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Endianness {
    /// Endianness has not been determined yet and should be auto-detected.
    #[default]
    Unknown,
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

impl Endianness {
    /// Parse an endianness from the textual CLI argument (`"le"` / `"be"`).
    ///
    /// Matches binbloom which accepts any case for the two characters.
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "le" => Ok(Endianness::Little),
            "be" => Ok(Endianness::Big),
            other => Err(BinbloomError::InvalidEndianness(other.to_string())),
        }
    }

    /// Short human-readable label, as printed by binbloom (`"LE"` / `"BE"`).
    pub fn label(self) -> &'static str {
        match self {
            Endianness::Unknown => "unknown",
            Endianness::Little => "LE",
            Endianness::Big => "BE",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(Endianness::parse("le").unwrap(), Endianness::Little);
        assert_eq!(Endianness::parse("LE").unwrap(), Endianness::Little);
        assert_eq!(Endianness::parse("be").unwrap(), Endianness::Big);
        assert_eq!(Endianness::parse("Be").unwrap(), Endianness::Big);
    }

    #[test]
    fn parse_invalid() {
        assert!(matches!(
            Endianness::parse("middle"),
            Err(BinbloomError::InvalidEndianness(_))
        ));
    }

    #[test]
    fn labels() {
        assert_eq!(Endianness::Little.label(), "LE");
        assert_eq!(Endianness::Big.label(), "BE");
    }

    #[test]
    fn default_is_unknown() {
        assert_eq!(Endianness::default(), Endianness::Unknown);
    }
}
