use std::{env, fs, path::PathBuf};

use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

fn object_bytes() -> Vec<u8> {
    let path = env::var_os("LANSPEED_EBPF_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/bpfel-unknown-none/release/lanspeed-ebpf")
        });
    fs::read(path).unwrap()
}

#[test]
fn kfunc_calls_materialize_the_required_bpf_argument_registers() {
    let bytes = object_bytes();
    let elf = object::File::parse(bytes.as_slice()).unwrap();
    for section in elf.sections() {
        let Some((file_offset, _)) = section.file_range() else {
            continue;
        };
        for (offset, relocation) in section.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let symbol = elf.symbol_by_index(index).unwrap();
            let Ok(name) = symbol.name() else { continue };
            let call = usize::try_from(file_offset + offset).unwrap();
            let (window_len, required): (usize, &[u8]) = match name {
                "bpf_skb_ct_lookup" => (8, &[1, 2, 4, 5]),
                "bpf_ct_release" => (1, &[1]),
                _ => continue,
            };
            let destinations = bytes[call - window_len * 8..call]
                .chunks_exact(8)
                .map(|instruction| instruction[1] & 0x0f)
                .collect::<Vec<_>>();
            for register in required {
                assert!(
                    destinations.contains(register),
                    "{name} does not set r{register} immediately before the call: {destinations:?}"
                );
            }
            if name == "bpf_skb_ct_lookup" {
                let block_destinations = bytes[call - 32 * 8..call]
                    .chunks_exact(8)
                    .map(|instruction| instruction[1] & 0x0f)
                    .collect::<Vec<_>>();
                assert!(
                    block_destinations.contains(&3),
                    "bpf_skb_ct_lookup does not materialize tuple_size in r3"
                );
            }
        }
    }
}
