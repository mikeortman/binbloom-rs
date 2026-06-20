// Standalone harness compiled against the crate to exercise the no-strings path.
use binbloom::{Arch, Endianness, Firmware};

fn main() {
    // Build a 32-bit LE firmware with NO printable strings.
    // base = 0x40000000. We need a "code" region by entropy so get_type(...)==Code.
    let base: u32 = 0x4000_0000;
    let total = 4096usize;
    let mut data = vec![0u8; total];

    // Code region [1024,2048): 128 distinct high bytes -> entropy ~0.875 (code band), no strings.
    for i in 0..1024 {
        data[1024 + i] = 0x80u8.wrapping_add((i % 128) as u8);
    }

    // Array of code pointers at offset 0 (12 pointers into the code region).
    // Each points at base + (1024 + k*4) which lands in the code region.
    // These must NOT be printable-ascii and must form a "value array" (each step < 0x1000).
    let n = 12usize;
    for k in 0..n {
        let code_target = 1024u32 + (k as u32) * 4; // inside code region, consecutive -> step 4
        let ptr = base + code_target; // 0x40000400, 0x40000404, ...
        data[k * 4..k * 4 + 4].copy_from_slice(&ptr.to_le_bytes());
    }

    // Verify no printable string of length >=8 accidentally exists in the pointer bytes.
    // 0x40000400 LE = 00 04 00 40 -> bytes 0x00 not printable. Good.

    let fw = Firmware::from_bytes(data, Arch::Bits32)
        .unwrap()
        .with_endianness(Endianness::Little);

    match fw.find_base_address(None) {
        Ok(a) => {
            println!(
                "OK base=0x{:x} confident={} reason={:?} tested={}",
                a.result.base_address,
                a.result.confident,
                a.result.reason,
                a.result.num_base_addresses_tested
            );
            for c in a.result.candidates.iter().take(5) {
                println!(
                    "  cand base=0x{:x} votes={} score={} valid_array={}",
                    c.base_address, c.votes, c.score, c.has_valid_array
                );
            }
        }
        Err(e) => println!("ERR {:?}", e),
    }
}
