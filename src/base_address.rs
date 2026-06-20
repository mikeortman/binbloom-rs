//! Base (loading) address recovery.
//!
//! The heuristic, faithful to binbloom:
//!
//! 1. Index points of interest (strings, then arrays of similar values).
//! 2. For every candidate base address, count how many in-file values look like
//!    pointers to a POI when interpreted relative to that base. Each such hit is
//!    a vote, accumulated in an [`AddrTree`].
//! 3. The address with the most votes is the prime suspect; a configurable set
//!    of high-vote candidates is then *refined* by a more expensive score that
//!    also rewards arrays of pointers resolving to known POIs.
//! 4. The final answer is chosen from the votes/score signals, with a
//!    confidence flag mirroring binbloom's "found" vs "seems to be (not sure)".

use crate::addrtree::AddrTree;
use crate::arch::Arch;
use crate::endianness::Endianness;
use crate::error::{BinbloomError, Result};
use crate::log::Logger;
use crate::memregion::{MemoryMap, RegionType};
use crate::poi::{PoiList, PoiType};
use crate::pointer::PointerReader;
use std::collections::HashSet;

/// Minimum string length to record (binbloom `STR_MIN_SIZE`).
pub const STR_MIN_SIZE: usize = 8;
/// Address-tree size cap that triggers a memory-saving filter (`MAX_MEM_AMOUNT`).
const MAX_MEM_AMOUNT: u64 = 4_000_000_000;
/// How many high-vote candidates binbloom keeps for refinement in normal mode.
const KEEP_TARGET: usize = 30;

/// Why a base address was selected, mirroring binbloom's output wording.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FoundReason {
    /// Exactly one candidate had an array of pointers fully resolving to POIs.
    ValidArray,
    /// The best-vote candidate and the best-score candidate agree.
    BestMatchAgrees,
    /// Selected from the refinement score (lower confidence).
    Score,
    /// Nothing scored; fell back to the best-vote candidate (lowest confidence).
    Fallback,
}

/// A refined candidate base address and its computed metrics.
#[derive(Clone, Copy, Debug)]
pub struct ScoredCandidate {
    pub base_address: u64,
    pub votes: i32,
    pub score: u64,
    pub has_valid_array: bool,
}

/// Outcome of a base-address search.
#[derive(Clone, Debug)]
pub struct BaseAddressResult {
    /// The chosen base address.
    pub base_address: u64,
    /// `true` for binbloom's "Base address found", `false` for "seems to be".
    pub confident: bool,
    /// Why this address was chosen.
    pub reason: FoundReason,
    /// Total number of distinct candidate addresses that received votes.
    pub num_base_addresses_tested: usize,
    /// Refined candidates, sorted by score (descending).
    pub candidates: Vec<ScoredCandidate>,
    /// Address to exclude from the "more candidates" list (`None` in the
    /// fallback case, where even the chosen address may be listed).
    pub more_exclude: Option<u64>,
}

/// A pre-refinement candidate (address + vote count).
#[derive(Clone, Copy)]
struct Candidate {
    address: u64,
    votes: i32,
}

/// Recovers the base address of a firmware image.
pub struct BaseAddressFinder<'a> {
    content: &'a [u8],
    reader: PointerReader,
    arch: Arch,
    memory: &'a MemoryMap,
    alignment_mask: u64,
    deep: bool,
    nb_threads: usize,
    ptr_aligned: bool,
    symbols: Option<&'a PoiList>,
    logger: Logger,
}

impl<'a> BaseAddressFinder<'a> {
    /// Build a finder. `alignment` is the candidate base-address alignment
    /// (binbloom default `0x1000`); `ptr_aligned` enables the optional
    /// pointer-alignment heuristic (the `-l` flag).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        content: &'a [u8],
        arch: Arch,
        endian: Endianness,
        memory: &'a MemoryMap,
        alignment: u64,
        deep: bool,
        nb_threads: usize,
        ptr_aligned: bool,
        symbols: Option<&'a PoiList>,
        logger: Logger,
    ) -> Self {
        BaseAddressFinder {
            content,
            reader: PointerReader::new(arch, endian),
            arch,
            memory,
            alignment_mask: alignment.wrapping_sub(1),
            deep,
            nb_threads: nb_threads.max(1),
            ptr_aligned,
            symbols,
            logger,
        }
    }

    /// Index points of interest: printable strings followed by arrays of
    /// similar consecutive values.
    pub fn index_poi(&self, include_strings: bool) -> PoiList {
        let mut list = PoiList::new();
        self.populate_poi(&mut list, include_strings);
        list
    }

    /// Append POIs (optional strings, then value arrays) to an existing list.
    /// Used when seeding from an external symbol list.
    pub fn populate_poi(&self, list: &mut PoiList, include_strings: bool) {
        if include_strings {
            list.append_strings(self.content, STR_MIN_SIZE);
        }
        self.append_value_arrays(list);
    }

    /// Append `Array` POIs: runs of >8 consecutive pointer-sized values where
    /// each step stays within 0x1000 of the previous one.
    fn append_value_arrays(&self, list: &mut PoiList) {
        let psize = self.reader.size();
        let all_ones = self.arch.max_value();
        let mut in_array = false;
        let mut start = 0u64;
        let mut count = 0i32;
        let mut prev = 0u64;

        let end = self.content.len().saturating_sub(psize);
        let mut cursor = 0usize;
        while cursor < end {
            let value = self.reader.read(self.content, cursor);
            if !in_array {
                if value != 0 && value != all_ones {
                    start = cursor as u64;
                    in_array = true;
                    count = 0;
                }
            } else if Self::value_delta_abs(value, prev) > 0x1000 {
                in_array = false;
                if count > 8 {
                    list.add(start, count, PoiType::Array);
                }
                count = 0;
            } else {
                count += 1;
            }
            prev = value;
            cursor += psize;
        }
    }

    /// binbloom compares array steps with `abs((int)(value - prev))`: the 64-bit
    /// difference is truncated to 32 bits and run through `abs`. We reproduce
    /// that exactly (including the `i32::MIN` saturation behaviour of glibc).
    fn value_delta_abs(value: u64, prev: u64) -> i32 {
        (value.wrapping_sub(prev) as u32 as i32).wrapping_abs()
    }

    /// Find arrays of code pointers when no strings are present, registering the
    /// pointed-to (masked) addresses as `Function` POIs.
    pub fn index_functions(&self, list: &mut PoiList) {
        let psize = self.reader.size();
        let max_code_addr = self.memory.max_code_addr();
        // z = log2(max_code_addr); guard the no-code case so the shift stays
        // non-negative (the loop body exits on the first miss there anyway).
        let z: i64 = if max_code_addr > 0 {
            (max_code_addr as f64).log2() as i64
        } else {
            0
        };

        let arrays: Vec<(u64, i32)> = list
            .iter()
            .filter(|p| p.poi_type == PoiType::Array)
            .map(|p| (p.offset, p.count))
            .collect();

        let mut additions: Vec<u64> = Vec::new();
        for (offset, count) in arrays {
            let mut k = count;
            let mut ba_mask = 0u64;
            let mut i = 31i64;
            while i >= 0 && i > (z - 1) && k == count {
                ba_mask = 0xffff_ffff_ffff_ffff_u64 << (i as u32);
                k = 1;
                let first = self.reader.read(self.content, offset as usize);
                if self.memory.get_type(first & !ba_mask) == RegionType::Code {
                    let ptr_h = first & ba_mask;
                    for j in 1..count {
                        let value = self
                            .reader
                            .read(self.content, offset as usize + j as usize * psize);
                        if (value & ba_mask) != ptr_h
                            || self.memory.get_type(value & !ba_mask) != RegionType::Code
                        {
                            break;
                        }
                        k += 1;
                    }
                }
                i -= 1;
            }

            if k == count {
                for idx in 0..count {
                    let value = self
                        .reader
                        .read(self.content, offset as usize + idx as usize * psize);
                    additions.push(value & !ba_mask);
                }
            }
        }

        for addr in additions {
            list.add_unique(addr, -1, PoiType::Function);
        }
    }

    /// Index plausible pointers for a given base address. A value is a pointer
    /// when it lands inside `[base, base + size)`, is non-zero, sits outside a
    /// code region itself, and resolves to a known (non-uninitialised) region.
    pub fn index_poi_pointers(&self, base: u64) -> PoiList {
        let mut list = PoiList::new();
        let psize = self.reader.size();
        let content_len = self.content.len() as u64;
        let end = self.content.len().saturating_sub(psize);

        let mut cursor = 0usize;
        while cursor < end {
            let value = self.reader.read(self.content, cursor);
            let here_is_code = self.memory.get_type(cursor as u64) == RegionType::Code;

            if let Some(symbols) = self.symbols {
                if !here_is_code {
                    for sym in symbols.iter() {
                        if value.wrapping_sub(base) == sym.offset
                            && sym.poi_type == PoiType::Function
                        {
                            list.add(cursor as u64, 1, PoiType::FunctionPointer);
                        }
                    }
                }
            } else if !here_is_code {
                let mem_type = self.memory.get_type(value.wrapping_sub(base));
                let in_range = value >= base && value < base.wrapping_add(content_len);
                if in_range
                    && value != 0
                    && mem_type != RegionType::Unknown
                    && mem_type != RegionType::UninitData
                {
                    if mem_type == RegionType::Code {
                        list.add(cursor as u64, 1, PoiType::FunctionPointer);
                    } else {
                        list.add(cursor as u64, 1, PoiType::GenericPointer);
                    }
                }
            }

            cursor += psize;
        }
        list
    }

    /// Run the full base-address search over an indexed POI list.
    pub fn compute_candidates(&self, poi_list: &PoiList) -> Result<BaseAddressResult> {
        if poi_list.is_empty() {
            return Err(BinbloomError::NoPointsOfInterest);
        }

        let has_str = poi_list.iter().any(|p| p.poi_type == PoiType::String);
        let tree = self.vote_candidates(poi_list, has_str);

        let leaves = tree.leaves();
        let num_tested = leaves.len();
        self.logger
            .message(&format!("[i] Found {num_tested} base addresses to test"));

        // Best by raw votes (lowest address wins ties, matching browse order).
        let mut best_vote_address = 0u64;
        let mut best_votes = -1i32;
        for &(addr, votes) in &leaves {
            if votes > best_votes {
                best_votes = votes;
                best_vote_address = addr;
            }
        }

        let max_votes = tree.max_vote();
        let mut candidates: Vec<Candidate> = leaves
            .iter()
            .filter(|&&(_, v)| (max_votes > 1 && v > 1) || max_votes == 1)
            .map(|&(address, votes)| Candidate { address, votes })
            .collect();
        candidates.sort_by_key(|c| std::cmp::Reverse(c.votes));

        let kept_count = self.kept_count(&candidates, max_votes);
        let kept = &candidates[..kept_count.min(candidates.len())];

        let scored = self.refine_candidates(kept, poi_list);

        // Best by refinement score (first/highest-vote wins ties).
        let mut best_score_address = u64::MAX;
        let mut best_score = 0u64;
        for sc in &scored {
            if sc.score > best_score {
                best_score = sc.score;
                best_score_address = sc.base_address;
            }
        }

        let valid_array_count = scored.iter().filter(|s| s.has_valid_array).count();
        let (base_address, confident, reason, more_exclude) = if valid_array_count == 1 {
            let chosen = scored
                .iter()
                .find(|s| s.has_valid_array)
                .unwrap()
                .base_address;
            (chosen, true, FoundReason::ValidArray, Some(chosen))
        } else if best_vote_address == best_score_address {
            (
                best_vote_address,
                true,
                FoundReason::BestMatchAgrees,
                Some(best_vote_address),
            )
        } else if best_score_address != u64::MAX {
            (
                best_score_address,
                false,
                FoundReason::Score,
                Some(best_score_address),
            )
        } else {
            // Nothing scored: report the best-vote address, but (as in binbloom)
            // do not exclude it from the "more candidates" list.
            (best_vote_address, false, FoundReason::Fallback, None)
        };

        let mut ranked = scored;
        ranked.sort_by_key(|c| std::cmp::Reverse(c.score));

        Ok(BaseAddressResult {
            base_address,
            confident,
            reason,
            num_base_addresses_tested: num_tested,
            candidates: ranked,
            more_exclude,
        })
    }

    /// Build the candidate-address vote tree (binbloom's first pass).
    fn vote_candidates(&self, poi_list: &PoiList, has_str: bool) -> AddrTree {
        let mut tree = AddrTree::new();
        let psize = self.reader.size();
        let max_value = self.arch.max_value();
        let content_len = self.content.len() as u64;

        for poi in poi_list.iter() {
            let mut cursor = 0usize;
            while cursor < self.content.len() {
                let v = self.reader.read(self.content, cursor);
                if (v & self.alignment_mask) == (poi.offset & self.alignment_mask)
                    && !self.reader.is_ascii_ptr(v)
                    && self.is_ptr_aligned(v)
                {
                    let want = (has_str && poi.poi_type == PoiType::String)
                        || (!has_str && poi.poi_type == PoiType::Function);
                    if want && v >= poi.offset {
                        let delta = v - poi.offset;
                        let freespace = max_value.wrapping_sub(delta).wrapping_add(1);
                        if freespace >= content_len {
                            tree.register_address(delta);
                        }
                    }
                }
                cursor += psize;
            }

            if tree.memsize() > MAX_MEM_AMOUNT {
                let mv = tree.max_vote();
                tree.filter(mv / 2);
            }
        }

        tree
    }

    /// Decide how many top candidates to refine. In deep mode, all of them;
    /// otherwise the smallest high-vote prefix containing at least 30.
    fn kept_count(&self, candidates: &[Candidate], max_votes: i32) -> usize {
        if self.deep {
            return candidates.len();
        }
        let mut kept = candidates.len();
        let mut i = max_votes;
        while i >= 0 {
            let c = candidates.iter().filter(|c| c.votes >= i).count();
            kept = c;
            if c >= KEEP_TARGET {
                break;
            }
            i -= 1;
        }
        kept
    }

    /// Refine candidates, optionally across threads. Order is preserved so the
    /// result is deterministic regardless of thread count or backend.
    ///
    /// The analysis itself is synchronous and runtime-agnostic: a single thread
    /// when `nb_threads <= 1`, otherwise the built-in `std::thread` backend, or
    /// rayon's work-stealing pool when the `rayon` feature is enabled.
    fn refine_candidates(&self, kept: &[Candidate], poi_list: &PoiList) -> Vec<ScoredCandidate> {
        if self.nb_threads <= 1 || kept.len() < 2 {
            return kept.iter().map(|c| self.refine_one(c, poi_list)).collect();
        }
        self.refine_parallel(kept, poi_list)
    }

    /// Built-in parallel backend: split candidates into contiguous chunks across
    /// scoped `std::thread`s, sharing `&self`/`&poi_list` read-only (no locks).
    #[cfg(not(feature = "rayon"))]
    fn refine_parallel(&self, kept: &[Candidate], poi_list: &PoiList) -> Vec<ScoredCandidate> {
        let n = kept.len();
        let nthreads = self.nb_threads.min(n);
        let chunk = n.div_ceil(nthreads);
        let mut results: Vec<ScoredCandidate> = Vec::with_capacity(n);

        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for slice in kept.chunks(chunk) {
                handles.push(scope.spawn(move || {
                    slice
                        .iter()
                        .map(|c| self.refine_one(c, poi_list))
                        .collect::<Vec<_>>()
                }));
            }
            for handle in handles {
                results.extend(handle.join().expect("refine thread panicked"));
            }
        });

        results
    }

    /// Rayon parallel backend (feature `rayon`): a work-stealing parallel map.
    ///
    /// `nb_threads` is honoured via a scoped pool so the `-t` flag stays
    /// meaningful; the indexed `collect` keeps results in candidate order, so
    /// the chosen base address is identical to the sequential path. If the pool
    /// cannot be built, it falls back to rayon's global pool.
    #[cfg(feature = "rayon")]
    fn refine_parallel(&self, kept: &[Candidate], poi_list: &PoiList) -> Vec<ScoredCandidate> {
        use rayon::prelude::*;
        let run = || {
            kept.par_iter()
                .map(|c| self.refine_one(c, poi_list))
                .collect::<Vec<_>>()
        };
        match rayon::ThreadPoolBuilder::new()
            .num_threads(self.nb_threads)
            .build()
        {
            Ok(pool) => pool.install(run),
            Err(_) => run(),
        }
    }

    /// Score a single candidate base address.
    fn refine_one(&self, candidate: &Candidate, poi_list: &PoiList) -> ScoredCandidate {
        let delta = candidate.address;
        let psize = self.reader.size();

        // binbloom keeps `array_score` and the final `score` in 32-bit unsigned
        // ints; the products are taken mod 2^32. We reproduce that so candidate
        // selection and ranking match the reference on large firmware.
        let mut array_score: u32 = 1;
        let mut found_valid_array = false;

        for poi in poi_list.iter().filter(|p| p.poi_type == PoiType::Array) {
            let mut distinct: HashSet<u64> = HashSet::new();
            for j in 0..poi.count {
                let v = self
                    .reader
                    .read(self.content, poi.offset as usize + j as usize * psize);
                let resolves = poi_list.iter().any(|zap| {
                    matches!(zap.poi_type, PoiType::String | PoiType::Array)
                        && v == zap.offset.wrapping_add(delta)
                });
                if resolves {
                    distinct.insert(v);
                }
            }
            // C counts these via a fresh address tree whose root is itself a
            // leaf, so an array that resolves nothing still contributes 1.
            let n_str_ptr = distinct.len().max(1);
            if n_str_ptr >= (poi.count as usize) / 3 && poi.count >= 10 {
                found_valid_array = true;
            }
            array_score = array_score.wrapping_add(n_str_ptr as u32);
        }

        let pointers = self.index_poi_pointers(delta);
        let score = (pointers.count() as u32)
            .wrapping_mul(candidate.votes as u32)
            .wrapping_mul(array_score) as u64;

        ScoredCandidate {
            base_address: delta,
            votes: candidate.votes,
            score,
            has_valid_array: found_valid_array,
        }
    }

    fn is_ptr_aligned(&self, address: u64) -> bool {
        if self.ptr_aligned {
            address % self.reader.size() as u64 == 0
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianness::Endianness;
    use crate::memregion::MemoryMap;
    use crate::poi::Poi;

    fn finder<'a>(
        content: &'a [u8],
        memory: &'a MemoryMap,
        arch: Arch,
        endian: Endianness,
    ) -> BaseAddressFinder<'a> {
        BaseAddressFinder::new(
            content,
            arch,
            endian,
            memory,
            0x1000,
            false,
            1,
            false,
            None,
            Logger::default(),
        )
    }

    #[test]
    fn value_delta_truncates_to_32_bits() {
        // Difference of exactly 0x1000 is not "> 0x1000".
        assert_eq!(BaseAddressFinder::value_delta_abs(0x1000, 0), 0x1000);
        assert_eq!(BaseAddressFinder::value_delta_abs(0, 0x1000), 0x1000);
        // Large 64-bit-only difference wraps in the low 32 bits.
        assert_eq!(
            BaseAddressFinder::value_delta_abs(0x1_0000_0005, 0x1_0000_0000),
            5
        );
    }

    #[test]
    fn index_value_arrays() {
        // 10 increasing 32-bit values, each +4 from the previous (< 0x1000),
        // then a far-away value to break the run (a run that reaches EOF is not
        // flushed, matching binbloom).
        let mut data = vec![0u8; 4];
        for i in 0..10u32 {
            data.extend_from_slice(&(0x100 + i * 4).to_le_bytes());
        }
        data.extend_from_slice(&0x5000u32.to_le_bytes()); // > 0x1000 jump -> breaks the run
        data.extend_from_slice(&[0u8; 8]); // padding past the end

        let mem = MemoryMap::new();
        let f = finder(&data, &mem, Arch::Bits32, Endianness::Little);
        let list = f.index_poi(false);
        let arrays: Vec<&Poi> = list
            .iter()
            .filter(|p| p.poi_type == PoiType::Array)
            .collect();
        assert_eq!(arrays.len(), 1);
        assert_eq!(arrays[0].offset, 4);
    }

    #[test]
    fn empty_poi_list_errors() {
        let data = vec![0u8; 64];
        let mem = MemoryMap::new();
        let f = finder(&data, &mem, Arch::Bits32, Endianness::Little);
        let empty = PoiList::new();
        assert!(matches!(
            f.compute_candidates(&empty),
            Err(BinbloomError::NoPointsOfInterest)
        ));
    }
}
