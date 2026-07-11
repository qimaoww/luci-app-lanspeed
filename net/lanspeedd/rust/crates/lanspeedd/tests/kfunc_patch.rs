use std::{env, fs, path::PathBuf};

use lanspeedd::{patch_conntrack_kfunc_calls_with, KfuncPatchError, KfuncTarget};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

fn object_bytes() -> Vec<u8> {
    let path = env::var_os("LANSPEED_EBPF_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/bpfel-unknown-none/release/lanspeed-ebpf")
        });
    fs::read(path).expect("build lanspeed-ebpf before this test")
}

#[test]
fn patches_both_conntrack_calls_to_kernel_btf_ids() {
    let mut bytes = object_bytes();
    patch_conntrack_kfunc_calls_with(&mut bytes, |name| -> Result<KfuncTarget, &'static str> {
        match name {
            "bpf_skb_ct_lookup" => Ok(KfuncTarget {
                type_id: 0x1234,
                btf_fd_index: 1,
            }),
            "bpf_ct_release" => Ok(KfuncTarget {
                type_id: 0x5678,
                btf_fd_index: 1,
            }),
            _ => unreachable!(),
        }
    })
    .unwrap();

    let elf = object::File::parse(bytes.as_slice()).unwrap();
    let mut patched = Vec::new();
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
            let expected = match name {
                "bpf_skb_ct_lookup" => 0x1234,
                "bpf_ct_release" => 0x5678,
                _ => continue,
            };
            let instruction_offset = usize::try_from(file_offset + offset).unwrap();
            let instruction = &bytes[instruction_offset..][..8];
            assert_eq!(instruction[1] >> 4, 2, "{name} is not a kfunc call");
            assert_eq!(i16::from_le_bytes(instruction[2..4].try_into().unwrap()), 1);
            assert_eq!(
                i32::from_le_bytes(instruction[4..8].try_into().unwrap()),
                expected
            );
            patched.push(name);
        }
    }
    patched.sort_unstable();
    assert_eq!(patched, ["bpf_ct_release", "bpf_skb_ct_lookup"]);
}

#[test]
fn reports_missing_kfunc_instead_of_deleting_connection_accounting() {
    let mut bytes = object_bytes();
    let original = bytes.clone();
    let error = patch_conntrack_kfunc_calls_with(&mut bytes, |name| {
        if name == "bpf_skb_ct_lookup" {
            Ok(KfuncTarget {
                type_id: 7,
                btf_fd_index: 0,
            })
        } else {
            Err("not in kernel BTF")
        }
    })
    .unwrap_err();

    assert!(matches!(
        error,
        KfuncPatchError::Resolve { name, .. } if name == "bpf_ct_release"
    ));
    assert_eq!(bytes, original);
}
