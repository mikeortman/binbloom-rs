//! `binbloom` command-line interface.
//!
//! Mirrors the original tool's flags and output. All analysis lives in the
//! library; this file only parses arguments, drives [`Firmware`] and prints
//! results. `main` is the sole free function (Rust's required entry point) and
//! immediately delegates to [`Cli::run`].

use binbloom::symbols::SymbolFile;
use binbloom::{
    Arch, BaseAddressAnalysis, Endianness, Firmware, FoundReason, LogLevel, Logger, PoiList,
    UdsResult,
};
use clap::Parser;
use std::process::ExitCode;

const VERSION: &str = "2.1.0";

/// Raw firmware analysis: endianness, base address and UDS database detection.
#[derive(Parser, Debug)]
#[command(name = "binbloom", version = VERSION, about, long_about = None)]
struct Cli {
    /// Target architecture: 32 or 64.
    #[arg(short = 'a', long = "arch", default_value = "32")]
    arch: String,

    /// Base address for UDS database search (enables UDS mode). Hex (`0x...`).
    #[arg(short = 'b', long = "base")]
    base: Option<String>,

    /// Force endianness: 'le' or 'be'.
    #[arg(short = 'e', long = "endian")]
    endian: Option<String>,

    /// Base address alignment (default 0x1000). Hex (`0x...`) or decimal.
    #[arg(short = 'm', long = "align")]
    align: Option<String>,

    /// Enable deep search (slower, considers every candidate).
    #[arg(short = 'd', long = "deep", default_value_t = false)]
    deep: bool,

    /// External file of known function addresses (`0x<hex> name` per line).
    #[arg(short = 'f', long = "functions")]
    functions: Option<String>,

    /// Number of refinement threads.
    #[arg(short = 't', long = "threads", default_value_t = 1)]
    threads: usize,

    /// Require candidate pointers to be naturally aligned.
    #[arg(short = 'l', long = "ptr-aligned", default_value_t = false)]
    ptr_aligned: bool,

    /// Verbose output (repeatable).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Firmware file to analyse ("-" reads from stdin).
    firmware: String,
}

impl Cli {
    fn run(self) -> ExitCode {
        let arch = match Arch::parse(&self.arch) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("[!] {e}");
                return ExitCode::FAILURE;
            }
        };
        match arch {
            Arch::Bits32 => println!("[i] 32-bit architecture selected."),
            Arch::Bits64 => println!("[i] 64-bit architecture selected."),
        }

        let endian = match self.endian.as_deref().map(Endianness::parse).transpose() {
            Ok(e) => e.unwrap_or(Endianness::Unknown),
            Err(e) => {
                eprintln!("[!] {e}");
                return ExitCode::FAILURE;
            }
        };
        match endian {
            Endianness::Little => println!("[i] Selected little-endian architecture."),
            Endianness::Big => println!("[i] Selected big-endian architecture."),
            Endianness::Unknown => {}
        }

        let alignment = match self.align.as_deref().map(Self::parse_number).transpose() {
            Ok(a) => a.unwrap_or(Firmware::DEFAULT_ALIGNMENT),
            Err(()) => {
                eprintln!("[!] invalid alignment value");
                return ExitCode::FAILURE;
            }
        };

        let logger = Logger::new(LogLevel::from_verbosity(self.verbose));

        let loaded = if self.firmware == "-" {
            Firmware::from_reader(std::io::stdin().lock(), arch)
        } else {
            Firmware::read(&self.firmware, arch)
        };
        let mut firmware = match loaded {
            Ok(fw) => fw,
            Err(e) => {
                eprintln!("[!] {e}");
                return ExitCode::FAILURE;
            }
        };
        firmware = firmware
            .with_endianness(endian)
            .with_alignment(alignment)
            .with_deep(self.deep)
            .with_threads(self.threads)
            .with_pointer_alignment(self.ptr_aligned)
            .with_logger(logger);

        println!("[i] File read ({} bytes)", firmware.len());

        // UDS mode: a base address was supplied.
        if let Some(base_str) = self.base.as_deref() {
            let base = match Self::parse_number(base_str) {
                Ok(b) => b,
                Err(()) => {
                    eprintln!("[!] invalid base address");
                    return ExitCode::FAILURE;
                }
            };
            println!("[i] Base address 0x{base:016x} provided.");
            return Self::run_uds(&firmware, base);
        }

        // Base-address mode (optionally seeded with a symbols file).
        let symbols = match self.functions.as_deref() {
            Some(path) => {
                let mut list = PoiList::new();
                if let Err(e) = SymbolFile::load(path, &mut list) {
                    eprintln!("[!] {e}");
                    return ExitCode::FAILURE;
                }
                Some(list)
            }
            None => None,
        };

        match firmware.find_base_address(symbols.as_ref()) {
            Ok(analysis) => {
                Self::print_base_address(&firmware, &analysis);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[!] {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn run_uds(firmware: &Firmware, base: u64) -> ExitCode {
        match firmware.find_uds(base) {
            Some(result) => {
                Self::print_uds(firmware, &result);
                ExitCode::SUCCESS
            }
            None => {
                println!("[!] No UDS database found.");
                ExitCode::SUCCESS
            }
        }
    }

    fn print_base_address(firmware: &Firmware, analysis: &BaseAddressAnalysis) {
        let arch = firmware.arch();
        let result = &analysis.result;
        let addr = result.base_address;

        let line = match (result.confident, result.reason) {
            (_, FoundReason::ValidArray) => {
                format!(
                    "[i] Base address found (valid array): {}",
                    Self::hex(addr, arch)
                )
            }
            (true, _) => format!("[i] Base address found: {}.", Self::hex(addr, arch)),
            (false, _) => format!(
                "[i] Base address seems to be {} (not sure).",
                Self::hex(addr, arch)
            ),
        };
        println!("{line}");

        // "More base addresses to consider", excluding the chosen one.
        let top_score = result.candidates.first().map(|c| c.score).unwrap_or(0);
        let extra: Vec<_> = result
            .candidates
            .iter()
            .filter(|c| Some(c.base_address) != result.more_exclude && c.score > 0)
            .take(30)
            .collect();

        if !extra.is_empty() {
            println!(" More base addresses to consider (just in case):");
            for c in extra {
                let ratio = if top_score > 0 {
                    c.score as f64 / top_score as f64
                } else {
                    0.0
                };
                println!("  {} ({:.2})", Self::hex(c.base_address, arch), ratio);
            }
        }
    }

    fn print_uds(firmware: &Firmware, result: &UdsResult) {
        println!(
            "Most probable UDS DB is located at {}, found {} different UDS RID",
            Self::hex(result.location, firmware.arch()),
            result.rid_count
        );
        println!("Identified structure:");
        print!("{}", result.structure_declaration());
    }

    /// Format an address as binbloom does: 8 hex digits for 32-bit, 16 for 64-bit.
    fn hex(value: u64, arch: Arch) -> String {
        match arch {
            Arch::Bits32 => format!("0x{:08x}", value as u32),
            Arch::Bits64 => format!("0x{value:016x}"),
        }
    }

    /// Parse a number that may be hex (`0x`/`0X` prefix) or decimal.
    fn parse_number(s: &str) -> std::result::Result<u64, ()> {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).map_err(|_| ())
        } else {
            s.parse::<u64>().map_err(|_| ())
        }
    }
}

fn main() -> ExitCode {
    Cli::parse().run()
}
