# binbloom-rs

A safe, from-scratch Rust reimplementation of [Quarkslab's binbloom](https://github.com/quarkslab/binbloom):
a tool that analyses a raw binary firmware image and determines, using
statistical heuristics, its **endianness**, its **base/loading address**, and
the location of an automotive **UDS database** (if any).

This port is `#![forbid(unsafe_code)]`, uses `thiserror` for error handling, is
multi-threaded for the expensive candidate-refinement step, and ships with an
extensive unit + integration test suite.

## Layout

It is split into a reusable **library crate** (`binbloom`) and a thin **binary**
(`binbloom`) that consumes it:

| Module | Responsibility |
|-|-|
| `arch` | Pointer width + entropy profile (`Arch`, `ArchInfo`) |
| `endianness` | `Endianness` enum and parsing |
| `pointer` | Decoding pointer-sized values (`PointerReader`) |
| `entropy` | Normalised Shannon entropy |
| `addrtree` | 256-way radix vote tree (`AddrTree`) |
| `poi` | Points of interest (`Poi`, `PoiList`, `PoiType`) |
| `memregion` | Entropy-based region classification (`MemoryMap`) |
| `symbols` | External symbol-file parser |
| `endian_detect` | Endianness detection (`EndiannessDetector`) |
| `base_address` | Base-address recovery (`BaseAddressFinder`) |
| `uds` | UDS database identification (`UdsFinder`) |
| `firmware` | High-level orchestrator (`Firmware`) |
| `log` | Leveled logger |

## CLI usage

```console
# Endianness + base address (32-bit by default, endianness auto-detected)
binbloom firmware.bin

# 64-bit, forced little-endian
binbloom -a 64 -e le firmware.bin

# Find the UDS database given a known base address
binbloom -a 32 -e be -b 0x0 firmware.bin

# Speed up refinement with threads; deep search
binbloom -t 8 -d firmware.bin
```

Flags mirror the original: `-a/--arch`, `-b/--base`, `-e/--endian`,
`-m/--align`, `-d/--deep`, `-f/--functions`, `-t/--threads`, `-l/--ptr-aligned`,
`-v/--verbose`.

## Library usage

```rust
use binbloom::{Arch, Endianness, Firmware};

let fw = Firmware::read("firmware.bin", Arch::Bits32)?
    .with_threads(8);

let analysis = fw.find_base_address(None)?;
println!("endianness: {:?}", analysis.endianness);
println!("base address: {:#x}", analysis.result.base_address);

if let Some(uds) = fw.find_uds(analysis.result.base_address) {
    println!("UDS DB @ {:#x} ({} RIDs)", uds.location, uds.rid_count);
}
# Ok::<(), binbloom::BinbloomError>(())
```

## Build & test

```console
cargo build --release
cargo test
cargo clippy --all-targets
```

## Differences from the C original

The behaviour is faithful to binbloom, with a few clear C bugs corrected (and
documented at their call sites):

- `arch_get_info` could loop forever on an unknown profile name; here it returns
  `None`.
- `poi_add_unique_sorted` linked the wrong node; here a proper sorted-unique
  insert is performed.
- Out-of-bounds pointer reads (which the C relies on staying in-bounds) are
  bounds-checked and zero-padded.
- The UDS RID dedup set is fully cleared between runs (the C `memset` cleared
  only part of it, mishandling RIDs ≥ 0x3F).

One faithfully-preserved quirk worth noting: a run of valid UDS request IDs is
only recorded when it is *terminated* by a non-RID/repeat byte, mirroring how
real UDS tables are bounded.

## License

Apache-2.0, as with the original binbloom.
