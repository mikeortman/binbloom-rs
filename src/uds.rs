//! UDS (Unified Diagnostic Services) database identification.
//!
//! Once a base address is known, binbloom looks for the request-ID table that
//! automotive ECUs keep as an array of fixed-size structures. The pipeline,
//! mirroring `find_coherent_data`:
//!
//! 1. index strings and pointers, then retype each pointer by what it targets;
//! 2. find runs of same-type pointers (`index_poi_pointer_arrays`);
//! 3. detect arrays of structures by spotting pointers repeating at a fixed
//!    stride (`index_poi_structure_arrays`);
//! 4. scan each structure column for the longest run of distinct, valid UDS
//!    request IDs (`identify_uds`).

use crate::arch::Arch;
use crate::base_address::{BaseAddressFinder, STR_MIN_SIZE};
use crate::endianness::Endianness;
use crate::log::Logger;
use crate::memregion::{MemoryMap, RegionType};
use crate::poi::{Poi, PoiList, PoiType};
use crate::pointer::PointerReader;
use std::collections::HashSet;

/// Maximum number of members a detected structure may have (`MAX_STRUCT_MEMBERS`).
const MAX_STRUCT_MEMBERS: usize = 12;

/// A located UDS database.
#[derive(Clone, Debug)]
pub struct UdsResult {
    /// Absolute address (base + offset) of the database.
    pub location: u64,
    /// Number of distinct valid UDS request IDs found.
    pub rid_count: usize,
    /// The structure whose column held the IDs (carries the signature).
    pub structure: Poi,
    /// Target architecture (for formatting the structure declaration).
    pub arch: Arch,
}

impl UdsResult {
    /// Render the identified structure as a C declaration, matching binbloom's
    /// `structure_disp_declaration`.
    pub fn structure_declaration(&self) -> String {
        let signature = match &self.structure.signature {
            Some(sig) => sig,
            None => return String::from("struct {\n}\n"),
        };
        let value_type = if self.arch == Arch::Bits32 {
            "uint32_t"
        } else {
            "uint64_t"
        };

        let mut out = String::from("struct {\n");
        let members = self.structure.nb_members as usize;
        for (field, &member) in signature.iter().take(members).enumerate() {
            let line = match member {
                -1 => format!("\t{value_type} field_{field};\n"),
                x if x == PoiType::String as i32 || x == PoiType::StringPointer as i32 => {
                    format!("\tchar *psz_field_{field};\n")
                }
                x if x == PoiType::PointerPointer as i32
                    || x == PoiType::StructurePointer as i32
                    || x == PoiType::GenericPointer as i32 =>
                {
                    format!("\tvoid *p_field_{field};\n")
                }
                x if x == PoiType::FunctionPointer as i32 => format!("\tcode *p_field_{field};\n"),
                x if x == PoiType::DataPointer as i32 => format!("\tdata *p_field_{field};\n"),
                x if x == PoiType::UninitDataPointer as i32 => {
                    format!("\tvar *p_field_{field};\n")
                }
                _ => format!("\t{value_type} dw_{field};\n"),
            };
            out.push_str(&line);
        }
        out.push_str("}\n");
        out
    }
}

/// Finds a UDS database in a firmware image given a known base address.
pub struct UdsFinder<'a> {
    content: &'a [u8],
    reader: PointerReader,
    arch: Arch,
    endian: Endianness,
    memory: &'a MemoryMap,
    logger: Logger,
}

impl<'a> UdsFinder<'a> {
    /// Create a finder.
    pub fn new(
        content: &'a [u8],
        arch: Arch,
        endian: Endianness,
        memory: &'a MemoryMap,
        logger: Logger,
    ) -> Self {
        UdsFinder {
            content,
            reader: PointerReader::new(arch, endian),
            arch,
            endian,
            memory,
            logger,
        }
    }

    /// Run the full coherent-data pipeline and return the most probable UDS
    /// database, or `None` if none is found.
    pub fn find(&self, base: u64) -> Option<UdsResult> {
        let strings = PoiList::index_strings(self.content, STR_MIN_SIZE);
        self.logger
            .message(&format!("[i] {} strings indexed", strings.count()));

        let mut pointers = self.index_pointers(base);
        self.retype_string_pointers(&mut pointers, &strings, base);
        self.retype_region_pointers(&mut pointers, base);

        let pointer_arrays = self.index_pointer_arrays(&pointers);

        let mut sorted = PoiList::new();
        for p in pointers.iter() {
            sorted.add_unique_sorted(p);
        }
        for p in pointer_arrays.iter() {
            sorted.add_unique_sorted(p);
        }

        let structures = self.index_structure_arrays(&sorted, &strings, base);
        self.identify_uds(&structures, base)
    }

    /// Index pointers using the shared base-address pointer scanner.
    fn index_pointers(&self, base: u64) -> PoiList {
        BaseAddressFinder::new(
            self.content,
            self.arch,
            self.endian,
            self.memory,
            0x1000,
            false,
            1,
            false,
            None,
            self.logger,
        )
        .index_poi_pointers(base)
    }

    /// Mark pointers that resolve to a known string as `StringPointer`.
    fn retype_string_pointers(&self, pointers: &mut PoiList, strings: &PoiList, base: u64) {
        let targets: HashSet<u64> = strings
            .iter()
            .map(|s| s.offset.wrapping_add(base))
            .collect();
        for poi in pointers.iter_mut() {
            let value = self.reader.read(self.content, poi.offset as usize);
            if targets.contains(&value) {
                poi.poi_type = PoiType::StringPointer;
            }
        }
    }

    /// Refine generic pointers into function/data/uninitialised-data pointers
    /// based on the region they point into.
    fn retype_region_pointers(&self, pointers: &mut PoiList, base: u64) {
        for poi in pointers.iter_mut() {
            if poi.poi_type >= PoiType::GenericPointer {
                let value = self.reader.read(self.content, poi.offset as usize);
                match self.memory.get_type(value.wrapping_sub(base)) {
                    RegionType::Code => poi.poi_type = PoiType::FunctionPointer,
                    RegionType::InitData => poi.poi_type = PoiType::DataPointer,
                    RegionType::UninitData => poi.poi_type = PoiType::UninitDataPointer,
                    RegionType::Unknown => {}
                }
            }
        }
    }

    /// Find runs of >4 consecutive same-type pointers.
    fn index_pointer_arrays(&self, pointers: &PoiList) -> PoiList {
        let psize = self.reader.size() as u64;
        let mut arrays = PoiList::new();

        let mut in_array = false;
        let mut count = 0i32;
        let mut start_offset = 0u64;
        let mut last_offset = 0u64;
        let mut array_type = PoiType::Unknown;

        for poi in pointers.iter() {
            if !in_array {
                count = 1;
                start_offset = poi.offset;
                last_offset = poi.offset;
                array_type = poi.poi_type;
                in_array = true;
            } else if poi.offset != last_offset + psize || poi.poi_type != array_type {
                if count > 4 {
                    arrays.add(start_offset, count, PoiType::ArrayPointer);
                }
                in_array = false;
            } else {
                count += 1;
                last_offset = poi.offset;
            }
        }
        arrays
    }

    /// Detect arrays of structures by finding pointers that repeat at a fixed
    /// stride. For each candidate pointer we try every structure size and keep
    /// the one yielding the longest run.
    fn index_structure_arrays(&self, pointers: &PoiList, strings: &PoiList, base: u64) -> PoiList {
        let psize = self.reader.size() as u64;
        let content_len = self.content.len() as u64;
        let scan_limit = content_len.saturating_sub(psize);

        let mut structures = PoiList::new();
        let mut min_offset = 0u64;

        for poi in pointers.iter() {
            if poi.offset < min_offset {
                continue;
            }

            let mut results = [0i32; MAX_STRUCT_MEMBERS];
            for nb_members in (2..=MAX_STRUCT_MEMBERS).rev() {
                let stride = nb_members as u64 * psize;
                let mut count = 0i32;
                loop {
                    let cursor = poi.offset + count as u64 * stride;
                    if cursor >= scan_limit {
                        break;
                    }
                    let found = pointers
                        .iter()
                        .any(|p2| p2.offset == cursor && p2.poi_type == poi.poi_type);
                    if found {
                        count += 1;
                    } else {
                        break;
                    }
                }
                results[nb_members - 1] = count;
            }

            // Pick the member count with the longest run (smallest size on ties).
            let mut opt_count = -1i32;
            let mut opt_nb_members = -1i32;
            for (i, &r) in results.iter().enumerate() {
                if r > opt_count {
                    opt_nb_members = i as i32 + 1;
                    opt_count = r;
                }
            }

            if opt_count > 3 && opt_nb_members >= 2 {
                let signature =
                    self.create_signature(pointers, strings, base, poi.offset, opt_nb_members);
                structures.add_structure_array(poi.offset, opt_count, opt_nb_members, &signature);
                min_offset = poi.offset + opt_count as u64 * (opt_nb_members as u64 * psize);
            }
        }

        structures
    }

    /// Build a per-member type signature for a structure starting at `offset`.
    fn create_signature(
        &self,
        pointers: &PoiList,
        strings: &PoiList,
        base: u64,
        offset: u64,
        nb_members: i32,
    ) -> Vec<i32> {
        let psize = self.reader.size() as u64;
        let mut sign = vec![-1i32; nb_members as usize];

        for (i, slot) in sign.iter_mut().enumerate() {
            let member_off = offset + i as u64 * psize;
            let value = self.reader.read(self.content, member_off as usize);
            let mut resolved = -1i32;

            // Is the member a pointer onto one of our recovered pointers, or is
            // it itself a known pointer?
            for item in pointers.iter() {
                if item.offset.wrapping_add(base) == value {
                    if item.poi_type >= PoiType::GenericPointer {
                        resolved = PoiType::PointerPointer as i32;
                        break;
                    }
                } else if item.offset == member_off {
                    resolved = item.poi_type as i32;
                    break;
                }
            }

            // Otherwise, does it point to a known string?
            if resolved < 0 {
                for item in strings.iter() {
                    if item.offset.wrapping_add(base) == value {
                        resolved = item.poi_type as i32;
                        break;
                    }
                }
            }

            // Still unknown: classify as a versatile value or plain unknown.
            if resolved < 0 {
                if value == 0 || value == 0xffff_ffff || value == 0xffff_ffff_ffff_ffff {
                    resolved = PoiType::NullPtrOrValue as i32;
                } else {
                    resolved = PoiType::Unknown as i32;
                }
            }

            *slot = resolved;
        }

        sign
    }

    /// Scan structure columns for the longest run of distinct valid UDS IDs.
    fn identify_uds(&self, structures: &PoiList, base: u64) -> Option<UdsResult> {
        let psize = self.reader.size() as u64;

        let mut best: Option<(u64, usize, usize, &Poi)> = None; // (column, run_len, start_elem, struct)

        for st in structures.iter() {
            let stride = st.nb_members as u64 * psize;
            let columns = st.nb_members as u64 * psize;

            for column in 0..columns {
                let mut seen: HashSet<u8> = HashSet::new();
                let mut count = 0usize;
                let mut start = 0usize;
                let mut in_seq = false;

                for k in 0..st.count as usize {
                    let idx = st.offset + k as u64 * stride + column;
                    let byte = self.content.get(idx as usize).copied().unwrap_or(0);

                    if Self::is_valid_uds_rid(byte) {
                        if !in_seq {
                            seen.clear();
                            in_seq = true;
                            start = k;
                            seen.insert(byte);
                            count = 1;
                        } else if seen.insert(byte) {
                            count += 1;
                        } else {
                            // Repeated RID ends the run.
                            in_seq = false;
                            Self::consider(&mut best, column, count, start, st);
                        }
                    } else {
                        in_seq = false;
                        Self::consider(&mut best, column, count, start, st);
                    }
                }
            }
        }

        let (column, run_len, start, st) = best?;
        if run_len == 0 {
            return None;
        }

        let location = st.offset + base + column + start as u64 * st.nb_members as u64 * psize;
        Some(UdsResult {
            location,
            rid_count: run_len,
            structure: st.clone(),
            arch: self.arch,
        })
    }

    fn consider<'p>(
        best: &mut Option<(u64, usize, usize, &'p Poi)>,
        column: u64,
        count: usize,
        start: usize,
        st: &'p Poi,
    ) {
        let better = match best {
            Some((_, best_len, _, _)) => count > *best_len,
            None => count > 0,
        };
        if better {
            *best = Some((column, count, start, st));
        }
    }

    /// Whether `value` is a valid UDS service request ID.
    pub fn is_valid_uds_rid(value: u8) -> bool {
        matches!(value,
            0x10 | 0x11 | 0x14 | 0x19
            | 0x27..=0x29
            | 0x3E
            | 0x83..=0x87
            | 0x22..=0x24
            | 0x2A | 0x2C | 0x2E | 0x2F | 0x31
            | 0x34..=0x38
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_rids_match_spec() {
        for v in [
            0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x24, 0x27, 0x28, 0x29, 0x2A, 0x2C, 0x2E, 0x2F,
            0x31, 0x34, 0x35, 0x36, 0x37, 0x38, 0x3E, 0x83, 0x84, 0x85, 0x86, 0x87,
        ] {
            assert!(UdsFinder::is_valid_uds_rid(v), "{v:#x} should be valid");
        }
        for v in [0x00u8, 0x01, 0x12, 0x20, 0x39, 0x80, 0x88, 0xff] {
            assert!(!UdsFinder::is_valid_uds_rid(v), "{v:#x} should be invalid");
        }
    }

    #[test]
    fn structure_declaration_renders_members() {
        let sig = vec![
            PoiType::FunctionPointer as i32,
            PoiType::StringPointer as i32,
            -1,
        ];
        let result = UdsResult {
            location: 0,
            rid_count: 3,
            structure: Poi {
                offset: 0,
                count: 5,
                signature: Some(sig),
                nb_members: 3,
                poi_type: PoiType::StructurePointer,
            },
            arch: Arch::Bits32,
        };
        let decl = result.structure_declaration();
        assert!(decl.contains("code *p_field_0;"));
        assert!(decl.contains("char *psz_field_1;"));
        assert!(decl.contains("uint32_t field_2;"));
    }
}
