use binbloom::base_address::BaseAddressFinder;
use binbloom::log::Logger;
use binbloom::{Arch, Endianness, Firmware, PoiType};

fn main() {
    let base: u32 = 0x4000_0000;
    let total = 4096usize;
    let mut data = vec![0u8; total];
    for i in 0..1024 {
        data[1024 + i] = 0x80u8.wrapping_add((i % 128) as u8);
    }
    let n = 12usize;
    for k in 0..n {
        let code_target = 1024u32 + (k as u32) * 4;
        let ptr = base + code_target;
        data[k * 4..k * 4 + 4].copy_from_slice(&ptr.to_le_bytes());
    }

    let fw = Firmware::from_bytes(data.clone(), Arch::Bits32)
        .unwrap()
        .with_endianness(Endianness::Little);
    let mem = fw.memory_map();
    println!("memory regions: {}", mem.len());
    for r in mem.iter() {
        println!(
            "  region off=0x{:x} size=0x{:x} type={:?} ent={:.3}",
            r.offset, r.size, r.region_type, r.entropy
        );
    }
    println!("max_code_addr=0x{:x}", mem.max_code_addr());
    println!("get_type(0x400)={:?}", mem.get_type(0x400));

    let finder = BaseAddressFinder::new(
        &data,
        Arch::Bits32,
        Endianness::Little,
        &mem,
        0x1000,
        false,
        1,
        false,
        None,
        Logger::default(),
    );
    let mut poi = finder.index_poi(true);
    println!("--- after index_poi(true) ---");
    for p in poi.iter() {
        println!(
            "  poi off=0x{:x} count={} type={:?}",
            p.offset, p.count, p.poi_type
        );
    }
    finder.index_functions(&mut poi);
    println!("--- after index_functions ---");
    for p in poi.iter() {
        println!(
            "  poi off=0x{:x} count={} type={:?}",
            p.offset, p.count, p.poi_type
        );
    }
}
