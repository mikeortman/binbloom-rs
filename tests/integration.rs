//! End-to-end tests over synthetic firmware images exercising the whole
//! pipeline through the public library API.

use binbloom::{Arch, Endianness, Firmware, FoundReason};

/// Build a 32-bit little-endian firmware whose base address is `0x60000000`:
/// twelve NUL-terminated strings, preceded by an array of twelve pointers that
/// each point at one of those strings (base + string offset).
fn base_address_firmware() -> (Vec<u8>, u64) {
    let base: u32 = 0x6000_0000;
    let n = 12usize;
    let str_start = 0x100usize;
    let stride = 0x10usize;

    let mut data = vec![0u8; str_start + n * stride];

    // Pointer array at offset 0: P_i = base + (str_start + i*stride).
    for i in 0..n {
        let target = (str_start + i * stride) as u32;
        let ptr = base + target;
        let p = i * 4;
        data[p..p + 4].copy_from_slice(&ptr.to_le_bytes());
    }

    // Strings, each at its referenced offset.
    for i in 0..n {
        let off = str_start + i * stride;
        let s = format!("string_{i:02}"); // 9 printable chars
        data[off..off + s.len()].copy_from_slice(s.as_bytes());
    }

    (data, base as u64)
}

/// Build a 32-bit firmware with an array of two-word structures whose second
/// word's low byte cycles through distinct valid UDS request IDs, with base
/// `0x20000000`. The first word of each structure points into a code region.
///
/// A trailing 13th structure carries an *invalid* RID byte: binbloom (and this
/// port) only records a RID run when it is terminated by a non-RID/repeat byte,
/// which mirrors how real UDS tables are bounded by a non-RID entry.
fn uds_firmware() -> (Vec<u8>, u64) {
    let base: u32 = 0x2000_0000;
    let total = 3072usize;
    let mut data = vec![0u8; total];

    // Code region [1024, 2048): 128 distinct non-printable bytes -> entropy
    // ~0.875 (code band) and no accidental strings.
    for i in 0..1024 {
        data[1024 + i] = 0x80u8.wrapping_add((i % 128) as u8);
    }

    // 12 valid RIDs followed by a terminating invalid one (0x00).
    let rids: [u8; 13] = [
        0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x24, 0x27, 0x28, 0x29, 0x2A, 0x2C, 0x00,
    ];
    for (k, &rid) in rids.iter().enumerate() {
        let off = k * 8; // [ptr:4][rid:1][pad:3]
        let code_target = 1024 + (k * 4) as u32; // inside the code region
        let ptr = base + code_target;
        data[off..off + 4].copy_from_slice(&ptr.to_le_bytes());
        data[off + 4] = rid;
    }

    (data, base as u64)
}

#[test]
fn finds_base_address_via_valid_array() {
    let (data, base) = base_address_firmware();
    let fw = Firmware::from_bytes(data, Arch::Bits32)
        .unwrap()
        .with_endianness(Endianness::Little);

    let analysis = fw.find_base_address(None).expect("analysis succeeds");
    assert_eq!(analysis.endianness, Endianness::Little);
    assert_eq!(analysis.result.base_address, base);
    assert!(analysis.result.confident);
    assert_eq!(analysis.result.reason, FoundReason::ValidArray);
}

#[test]
fn base_address_is_stable_across_thread_counts() {
    let (data, base) = base_address_firmware();
    for threads in [1usize, 2, 4, 8] {
        let fw = Firmware::from_bytes(data.clone(), Arch::Bits32)
            .unwrap()
            .with_endianness(Endianness::Little)
            .with_threads(threads);
        let analysis = fw.find_base_address(None).unwrap();
        assert_eq!(
            analysis.result.base_address, base,
            "thread count {threads} changed the result"
        );
    }
}

#[test]
fn detects_endianness_little_and_big() {
    // Many 4-aligned pointers sharing high bytes 0x0800 -> strong endian signal.
    let mut le = Vec::new();
    let mut be = Vec::new();
    for i in 0..4000u32 {
        let ptr = 0x0800_0000 + ((i * 4) & 0xffff);
        le.extend_from_slice(&ptr.to_le_bytes());
        be.extend_from_slice(&ptr.to_be_bytes());
    }

    let fw_le = Firmware::from_bytes(le, Arch::Bits32).unwrap();
    assert_eq!(fw_le.resolve_endianness(), Endianness::Little);

    let fw_be = Firmware::from_bytes(be, Arch::Bits32).unwrap();
    assert_eq!(fw_be.resolve_endianness(), Endianness::Big);
}

#[test]
fn finds_uds_database() {
    let (data, base) = uds_firmware();
    let fw = Firmware::from_bytes(data, Arch::Bits32)
        .unwrap()
        .with_endianness(Endianness::Little);

    let uds = fw.find_uds(base, None).expect("a UDS database is found");
    assert_eq!(uds.rid_count, 12);
    assert_eq!(uds.location, base + 4);
    assert_eq!(uds.structure.nb_members, 2);

    let decl = uds.structure_declaration();
    assert!(decl.starts_with("struct {"));
    assert!(decl.contains("code *p_field_0;")); // member 0 points to code
}

#[test]
fn rejects_too_small_image() {
    let err = Firmware::from_bytes(vec![0u8; 2], Arch::Bits64);
    assert!(err.is_err());
}

#[test]
fn cli_reports_base_address() {
    use std::io::Write;
    use std::process::Command;

    let (data, _base) = base_address_firmware();
    let mut path = std::env::temp_dir();
    path.push(format!("binbloom_cli_{}.bin", std::process::id()));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&data)
        .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_binbloom"))
        .args(["-a", "32", "-e", "le"])
        .arg(&path)
        .output()
        .expect("binary runs");

    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "exit: {:?}", output.status);
    assert!(
        stdout.contains("0x60000000"),
        "expected base address in output:\n{stdout}"
    );
    assert!(stdout.contains("Base address"));
}
