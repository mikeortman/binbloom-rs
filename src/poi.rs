//! Points of interest (POIs): strings, value arrays, pointers and structures
//! discovered in the firmware.
//!
//! The C version threads these on a hand-rolled singly linked list with a
//! sentinel head; we use a `Vec` (preserving insertion order, which several
//! heuristics depend on) and methods that mirror the original `poi_*` API.

use crate::arch::Arch;

/// Kind of point of interest.
///
/// The discriminant order is significant: binbloom compares types with `>=`
/// (e.g. "is this any kind of pointer?" is `type >= GenericPointer`), so the
/// declaration order here must match the C enum exactly. `PartialOrd`/`Ord` are
/// derived from this order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PoiType {
    Unknown = 0,
    String = 1,
    Array = 2,
    Structure = 3,
    Function = 4,

    GenericPointer = 5,
    DataPointer = 6,
    UninitDataPointer = 7,
    FunctionPointer = 8,
    ArrayPointer = 9,
    StringPointer = 10,
    PointerPointer = 11,
    StructurePointer = 12,
    StructArrayPointer = 13,

    NullPtrOrValue = 14,
}

impl PoiType {
    /// Numeric value used when a POI type is stored inside a structure
    /// signature (which also uses `-1` for "unknown member").
    pub fn as_signature(self) -> i32 {
        self as i32
    }
}

/// A single point of interest.
#[derive(Clone, Debug)]
pub struct Poi {
    /// Offset of the POI inside the firmware image.
    pub offset: u64,
    /// Length (in elements) for arrays/structures, or a small flag otherwise.
    pub count: i32,
    /// Per-member type signature for structure arrays.
    pub signature: Option<Vec<i32>>,
    /// Number of members for structure arrays.
    pub nb_members: i32,
    /// Kind of POI.
    pub poi_type: PoiType,
}

impl Poi {
    /// Create a plain (non-structure) POI.
    pub fn new(offset: u64, count: i32, poi_type: PoiType) -> Self {
        Poi {
            offset,
            count,
            signature: None,
            nb_members: 0,
            poi_type,
        }
    }
}

/// An ordered collection of points of interest.
#[derive(Clone, Debug, Default)]
pub struct PoiList {
    items: Vec<Poi>,
}

impl PoiList {
    /// Create an empty list.
    pub fn new() -> Self {
        PoiList { items: Vec::new() }
    }

    /// Number of POIs in the list.
    pub fn count(&self) -> usize {
        self.items.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterate over the POIs in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, Poi> {
        self.items.iter()
    }

    /// Mutably iterate over the POIs in insertion order.
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, Poi> {
        self.items.iter_mut()
    }

    /// Append a POI unconditionally.
    pub fn add(&mut self, offset: u64, count: i32, poi_type: PoiType) {
        self.items.push(Poi::new(offset, count, poi_type));
    }

    /// Append a POI only if no existing POI shares the same offset.
    /// Returns `true` when a new POI was inserted.
    pub fn add_unique(&mut self, offset: u64, count: i32, poi_type: PoiType) -> bool {
        if self.items.iter().any(|p| p.offset == offset) {
            return false;
        }
        self.items.push(Poi::new(offset, count, poi_type));
        true
    }

    /// Insert a copy of `poi` keeping the list sorted by offset, skipping it if
    /// the offset is already present.
    ///
    /// The C `poi_add_unique_sorted` has a bug where it links the *original*
    /// node instead of the freshly allocated copy; we do the correct, safe
    /// thing here (insert a copy at the sorted position).
    pub fn add_unique_sorted(&mut self, poi: &Poi) {
        let mut insert_at = self.items.len();
        for (i, existing) in self.items.iter().enumerate() {
            if existing.offset == poi.offset {
                return;
            }
            if existing.offset > poi.offset {
                insert_at = i;
                break;
            }
        }
        // Copies preserve the POI's type/count but not structure metadata,
        // matching how the C copy path populates the new node.
        let mut copy = Poi::new(poi.offset, poi.count, poi.poi_type);
        copy.nb_members = 0;
        copy.signature = None;
        self.items.insert(insert_at, copy);
    }

    /// Add a structure-array POI (with its per-member signature), unique by
    /// offset. Returns `true` when inserted.
    pub fn add_structure_array(
        &mut self,
        offset: u64,
        count: i32,
        nb_members: i32,
        signature: &[i32],
    ) -> bool {
        if self.items.iter().any(|p| p.offset == offset) {
            return false;
        }
        self.items.push(Poi {
            offset,
            count,
            signature: Some(signature.to_vec()),
            nb_members,
            poi_type: PoiType::StructurePointer,
        });
        true
    }

    /// Build a fresh list containing the printable-string POIs of `content`.
    pub fn index_strings(content: &[u8], min_size: usize) -> Self {
        let mut list = PoiList::new();
        list.append_strings(content, min_size);
        list
    }

    /// Append printable-ASCII runs of at least `min_size` bytes as `String`
    /// POIs. Mirrors `index_poi_strings`: a run that reaches the end of the
    /// buffer without a terminating non-printable byte is *not* recorded.
    pub fn append_strings(&mut self, content: &[u8], min_size: usize) {
        // The run length is derived from buffer positions (in `usize`) rather
        // than an incrementing counter, so it cannot overflow/panic on a
        // multi-gigabyte printable run. The stored `count` wraps into `i32`
        // exactly like binbloom's `int count` field.
        let mut start: Option<usize> = None;
        for (cursor, &b) in content.iter().enumerate() {
            let printable = Self::is_print(b);
            match (start, printable) {
                (None, true) => start = Some(cursor),
                (Some(begin), false) => {
                    let len = cursor - begin;
                    if len >= min_size {
                        self.add(begin as u64, len as i32, PoiType::String);
                    }
                    start = None;
                }
                _ => {}
            }
        }
    }

    /// C `isprint`: printable ASCII, space (0x20) through tilde (0x7e).
    fn is_print(b: u8) -> bool {
        (0x20..=0x7e).contains(&b)
    }

    /// Whether `address` falls inside a known string or array POI, given a base
    /// `offset` (base address). Mirrors `is_in_poi`.
    pub fn is_in(&self, arch: Arch, address: u64, offset: u64) -> bool {
        let arch_size = arch.pointer_size() as u64;
        for poi in &self.items {
            match poi.poi_type {
                PoiType::String => {
                    if address == poi.offset + offset {
                        return true;
                    }
                }
                PoiType::Array => {
                    let start = poi.offset + offset;
                    let end = start + poi.count as u64 * arch_size;
                    if address >= start && address < end {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_ordering_matches_c() {
        // "Is any kind of pointer" == `type >= GenericPointer` in binbloom.
        assert!(PoiType::FunctionPointer >= PoiType::GenericPointer);
        assert!(PoiType::String < PoiType::GenericPointer);
        assert_eq!(PoiType::NullPtrOrValue as i32, 14);
        assert_eq!(PoiType::String.as_signature(), 1);
    }

    #[test]
    fn add_and_count() {
        let mut list = PoiList::new();
        list.add(0x10, 8, PoiType::String);
        list.add(0x20, 4, PoiType::Array);
        assert_eq!(list.count(), 2);
        let offsets: Vec<u64> = list.iter().map(|p| p.offset).collect();
        assert_eq!(offsets, vec![0x10, 0x20]);
    }

    #[test]
    fn add_unique_dedupes_by_offset() {
        let mut list = PoiList::new();
        assert!(list.add_unique(0x10, 1, PoiType::Function));
        assert!(!list.add_unique(0x10, 1, PoiType::Function));
        assert_eq!(list.count(), 1);
    }

    #[test]
    fn add_unique_sorted_keeps_order() {
        let mut list = PoiList::new();
        for off in [0x30u64, 0x10, 0x20, 0x10] {
            list.add_unique_sorted(&Poi::new(off, 1, PoiType::GenericPointer));
        }
        let offsets: Vec<u64> = list.iter().map(|p| p.offset).collect();
        assert_eq!(offsets, vec![0x10, 0x20, 0x30]);
    }

    #[test]
    fn structure_array_stores_signature() {
        let mut list = PoiList::new();
        let sig = [PoiType::FunctionPointer.as_signature(), -1, 2];
        assert!(list.add_structure_array(0x100, 5, 3, &sig));
        assert!(!list.add_structure_array(0x100, 9, 3, &sig));
        let poi = list.iter().next().unwrap();
        assert_eq!(poi.poi_type, PoiType::StructurePointer);
        assert_eq!(poi.nb_members, 3);
        assert_eq!(poi.signature.as_deref(), Some(sig.as_slice()));
    }

    #[test]
    fn index_strings_finds_runs() {
        // "HELLO!!" (7) is too short for min 8; "binbloom_rocks" (14) qualifies.
        let mut data = b"\x00HELLO!!\x00".to_vec();
        data.extend_from_slice(b"binbloom_rocks\x00");
        let list = PoiList::index_strings(&data, 8);
        assert_eq!(list.count(), 1);
        let poi = list.iter().next().unwrap();
        assert_eq!(poi.poi_type, PoiType::String);
        assert_eq!(poi.offset, 9);
        assert_eq!(poi.count, 14);
    }

    #[test]
    fn index_strings_drops_unterminated_trailing_run() {
        // No terminating non-printable byte -> not recorded (matches C).
        let data = b"abcdefghij".to_vec();
        let list = PoiList::index_strings(&data, 8);
        assert_eq!(list.count(), 0);
    }

    #[test]
    fn is_in_string_and_array() {
        let mut list = PoiList::new();
        list.add(0x10, 8, PoiType::String);
        list.add(0x40, 4, PoiType::Array);
        let base = 0x8000_0000;
        // String matches only its exact start.
        assert!(list.is_in(Arch::Bits32, base + 0x10, base));
        assert!(!list.is_in(Arch::Bits32, base + 0x11, base));
        // Array matches its whole span [0x40, 0x40 + 4*4).
        assert!(list.is_in(Arch::Bits32, base + 0x40, base));
        assert!(list.is_in(Arch::Bits32, base + 0x4f, base));
        assert!(!list.is_in(Arch::Bits32, base + 0x50, base));
    }
}
