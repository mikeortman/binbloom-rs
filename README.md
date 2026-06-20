# binbloom

A **pure-Rust, memory-safe port** of [Quarkslab's binbloom](https://github.com/quarkslab/binbloom):
a tool that analyses a raw binary firmware image and determines, using
statistical heuristics, its **endianness**, its **base/loading address**, and
the location of an automotive **UDS database** (if any).

It is a faithful, from-scratch reimplementation that aims to produce the same
results as the original C tool while being safe by construction: it contains
**no `unsafe` code** (`#![forbid(unsafe_code)]`) and ships with an extensive
unit + integration test suite. The expensive candidate-refinement step can be
parallelised, with **optional multithreading via [rayon](https://crates.io/crates/rayon)**
behind a Cargo feature.

Versioning tracks upstream: this crate's **`2.1.0`** corresponds to binbloom
**`v2.1`**. Released under the **Apache-2.0** license, matching the original
([quarkslab/binbloom](https://github.com/quarkslab/binbloom)).

```console
cargo add binbloom        # library
cargo install binbloom    # CLI
```

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

# Read the image from a stream instead of a file ("-" = stdin)
cat firmware.bin | binbloom -a 32 -e le -
```

Flags mirror the original: `-a/--arch`, `-b/--base`, `-e/--endian`,
`-m/--align`, `-d/--deep`, `-f/--functions`, `-t/--threads`, `-l/--ptr-aligned`,
`-v/--verbose`.

## Library usage

```rust
use binbloom::{Arch, Endianness, Firmware};

// From a file, or from any `Read` stream via `Firmware::from_reader(...)`.
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

## Parallelism

The analysis is **synchronous and runtime-agnostic** — it pulls in no async
runtime, so it drops cleanly into a plain `main`, a tokio app
(`tokio::task::spawn_blocking`), or a rayon task. The expensive step
(candidate refinement) is parallelised; everything is read-only shared across
threads, so there are no locks and the result is deterministic regardless of
thread count.

Two interchangeable backends, selected at compile time:

| Backend | When | Notes |
|-|-|-|
| `std::thread` | default | Scoped threads, contiguous chunks, zero extra deps |
| `rayon` | `--features rayon` | Work-stealing pool, better load balancing |

The `-t/--threads` flag controls the worker count in both (default 1; `<= 1`
runs sequentially). The `rayon` feature is opt-in so the dependency is never
forced on library consumers.

## Build & test

```console
cargo build --release                  # std::thread backend
cargo build --release --features rayon # rayon backend
cargo test                  # and: cargo test --features rayon
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

For everything else the goal is **identical output to binbloom on the same
input**, so the port deliberately reproduces the reference's 32-bit `unsigned
int` arithmetic where it affects results — the refinement `score` and
`array_score`, the address-tree `memsize` used by the memory-saving filter, and
the array-detection value deltas all wrap mod 2³² exactly as the C does (done
with checked `wrapping_*` ops, so there is no `unsafe` and no overflow panic).

Faithfully-preserved quirks worth noting:

- A run of valid UDS request IDs is only recorded when it is *terminated* by a
  non-RID/repeat byte, mirroring how real UDS tables are bounded.
- The symbol file (`-f`) only accepts `\n`-terminated `0x<hex> ` lines, and a
  supplied symbol file is honored in both base-address and UDS modes.

## License

Apache-2.0, as with the original binbloom.
