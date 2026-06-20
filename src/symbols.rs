//! Parser for an external symbol/function-address file.
//!
//! Each useful line looks like `0x<hex> <name>` (anything before the `0x` is
//! skipped). The hex value is taken as a known function address and added as a
//! `Function` POI. Mirrors binbloom's `read_poi_from_file`, but expressed as a
//! straightforward line scan instead of the original byte-buffer state machine.

use crate::error::{BinbloomError, Result};
use crate::poi::{PoiList, PoiType};
use std::path::Path;

/// Loads function addresses from a symbol file.
pub struct SymbolFile;

impl SymbolFile {
    /// Read `path` and append every parsed function address to `list`
    /// (deduplicated by offset). Returns the number of symbols added.
    pub fn load(path: impl AsRef<Path>, list: &mut PoiList) -> Result<usize> {
        let path = path.as_ref();
        let content =
            std::fs::read_to_string(path).map_err(|source| BinbloomError::FileAccess {
                path: path.display().to_string(),
                source,
            })?;
        Ok(Self::parse_into(&content, list))
    }

    /// Parse symbol-file `text`, appending function POIs to `list`. Returns the
    /// number of symbols added. Split out for testability.
    pub fn parse_into(text: &str, list: &mut PoiList) -> usize {
        let mut added = 0;
        for line in text.lines() {
            if let Some(address) = Self::parse_line(line) {
                if list.add_unique(address, 1, PoiType::Function) {
                    added += 1;
                }
            }
        }
        added
    }

    /// Extract the address from a single line, if it is well-formed:
    /// the first `0x`-prefixed token followed by whitespace and a name.
    fn parse_line(line: &str) -> Option<u64> {
        let start = line.find("0x").or_else(|| line.find("0X"))?;
        let rest = &line[start + 2..];

        // The hex digits run until the first whitespace; a name must follow.
        let hex_end = rest.find(char::is_whitespace)?;
        let hex = &rest[..hex_end];
        let name = rest[hex_end..].trim();
        if hex.is_empty() || name.is_empty() {
            return None;
        }

        u64::from_str_radix(hex, 16).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_lines() {
        let text = "0x08001000 reset_handler\n0x08001234 main\n";
        let mut list = PoiList::new();
        let n = SymbolFile::parse_into(text, &mut list);
        assert_eq!(n, 2);
        let offsets: Vec<u64> = list.iter().map(|p| p.offset).collect();
        assert_eq!(offsets, vec![0x0800_1000, 0x0800_1234]);
        assert!(list.iter().all(|p| p.poi_type == PoiType::Function));
    }

    #[test]
    fn dedupes_repeated_addresses() {
        let text = "0x1000 a\n0x1000 b\n";
        let mut list = PoiList::new();
        assert_eq!(SymbolFile::parse_into(text, &mut list), 1);
        assert_eq!(list.count(), 1);
    }

    #[test]
    fn skips_lines_without_name() {
        // No trailing name -> ignored.
        let text = "0x2000\n0x3000 named\n";
        let mut list = PoiList::new();
        assert_eq!(SymbolFile::parse_into(text, &mut list), 1);
        assert_eq!(list.iter().next().unwrap().offset, 0x3000);
    }

    #[test]
    fn skips_non_hex_and_blank_lines() {
        let text = "\n# a comment\nnot an address here\n0xdeadbeef func\n";
        let mut list = PoiList::new();
        assert_eq!(SymbolFile::parse_into(text, &mut list), 1);
        assert_eq!(list.iter().next().unwrap().offset, 0xdead_beef);
    }

    #[test]
    fn tolerates_leading_garbage_before_0x() {
        let text = "  junk 0x40 sym\n";
        let mut list = PoiList::new();
        assert_eq!(SymbolFile::parse_into(text, &mut list), 1);
        assert_eq!(list.iter().next().unwrap().offset, 0x40);
    }

    #[test]
    fn missing_file_errors() {
        let mut list = PoiList::new();
        let err = SymbolFile::load("/nonexistent/path/to/symbols.txt", &mut list);
        assert!(matches!(err, Err(BinbloomError::FileAccess { .. })));
    }
}
