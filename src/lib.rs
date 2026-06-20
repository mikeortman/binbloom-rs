//! A pure-Rust, memory-safe port of Quarkslab's `binbloom`
//! (<https://github.com/quarkslab/binbloom>), released under the Apache-2.0
//! license to match the original.
//!
//! `binbloom` analyses a raw binary firmware image and tries to determine,
//! using statistical heuristics, three things:
//!
//! * its **endianness** (little or big endian),
//! * its **base/loading address**, and
//! * the location of an automotive **UDS database** (if any).
//!
//! The crate is organised as a set of focused types, each owning the data and
//! the operations it is responsible for. It contains no `unsafe` code, and the
//! expensive refinement step can be parallelised (optionally via rayon, behind
//! the `rayon` feature).
//!
//! The public entry point is [`Firmware`], which wires the individual engines
//! ([`EndiannessDetector`], [`BaseAddressFinder`], [`UdsFinder`]) together.

#![forbid(unsafe_code)]

pub mod addrtree;
pub mod arch;
pub mod base_address;
pub mod endian_detect;
pub mod endianness;
pub mod entropy;
pub mod error;
pub mod firmware;
pub mod log;
pub mod memregion;
pub mod poi;
pub mod pointer;
pub mod symbols;
pub mod uds;

pub use arch::{Arch, ArchInfo};
pub use base_address::{BaseAddressFinder, BaseAddressResult, FoundReason, ScoredCandidate};
pub use endian_detect::EndiannessDetector;
pub use endianness::Endianness;
pub use error::{BinbloomError, Result};
pub use firmware::{BaseAddressAnalysis, Firmware};
pub use log::{LogLevel, Logger};
pub use memregion::{MemRegion, MemoryMap, RegionType};
pub use poi::{Poi, PoiList, PoiType};
pub use pointer::PointerReader;
pub use uds::{UdsFinder, UdsResult};
