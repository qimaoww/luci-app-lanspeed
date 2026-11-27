use std::fs;

use aya_obj::btf::{Btf, BtfKind};
use lanspeedd::{merge_split_btf, KfuncPatchError};
use object::Endianness;

#[test]
fn merges_module_btf_with_vmlinux_type_and_string_bases() {
    let base_strings = b"\0int\0";
    let base = btf(&[1, (BtfKind::Int as u32) << 24, 4, 32], base_strings);
    let function_name = base_strings.len() as u32;
    // The prototype returns base type 1 and the function references that
    // prototype (type 2) and the first string from the split section.
    let prototype = [0, (BtfKind::FuncProto as u32) << 24, 1];
    let function = [function_name, ((BtfKind::Func as u32) << 24) | 1, 2];
    let split = btf(&[prototype, function].concat(), b"lanspeed_test_fn\0");
    let merged = merge_split_btf(&base, &split).unwrap();
    let btf = Btf::parse(&merged, Endianness::Little).unwrap();
    assert_eq!(btf.id_by_type_name_kind("int", BtfKind::Int).unwrap(), 1);
    assert_eq!(
        btf.id_by_type_name_kind("lanspeed_test_fn", BtfKind::Func)
            .unwrap(),
        3
    );
}

#[test]
#[ignore = "requires vmlinux and split nf_conntrack BTF exported by the host kernel"]
fn merges_host_conntrack_module_btf() {
    let base_bytes = fs::read("/sys/kernel/btf/vmlinux").unwrap();
    let module_bytes = fs::read("/sys/kernel/btf/nf_conntrack").unwrap();
    let base = Btf::parse(&base_bytes, Endianness::Little).unwrap();

    let merged = merge_split_btf(&base_bytes, &module_bytes).unwrap();
    let btf = Btf::parse(&merged, Endianness::Little).unwrap();
    let lookup = btf
        .id_by_type_name_kind("bpf_skb_ct_lookup", BtfKind::Func)
        .unwrap();
    let release = btf
        .id_by_type_name_kind("bpf_ct_release", BtfKind::Func)
        .unwrap();
    eprintln!("lookup={lookup} release={release}");
    for (name, id) in [("bpf_skb_ct_lookup", lookup), ("bpf_ct_release", release)] {
        assert!(base.id_by_type_name_kind(name, BtfKind::Func).is_err());
        assert!(id > 0);
    }
}

#[test]
fn malformed_btf_offsets_and_header_lengths_return_errors() {
    let valid = btf_header(24, 0, 0, 0, 0);
    for malformed in [
        btf_header(0, 0, 0, 0, 0),
        btf_header(u32::MAX, 0, 0, 0, 0),
        btf_header(24, u32::MAX, u32::MAX, 0, 0),
        btf_header(24, 0, 0, u32::MAX, u32::MAX),
    ] {
        assert!(matches!(
            merge_split_btf(&malformed, &valid),
            Err(KfuncPatchError::InvalidBtf(_))
        ));
        assert!(matches!(
            merge_split_btf(&valid, &malformed),
            Err(KfuncPatchError::InvalidBtf(_))
        ));
    }
}

fn btf(types: &[u32], strings: &[u8]) -> Vec<u8> {
    let type_len = (types.len() * 4) as u32;
    let mut bytes = btf_header(24, 0, type_len, type_len, strings.len() as u32);
    for word in types {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(strings);
    bytes
}

fn btf_header(
    header_len: u32,
    type_offset: u32,
    type_len: u32,
    string_offset: u32,
    string_len: u32,
) -> Vec<u8> {
    let mut bytes = vec![0u8; 24];
    bytes[..2].copy_from_slice(&0xeb9fu16.to_le_bytes());
    bytes[2] = 1;
    bytes[4..8].copy_from_slice(&header_len.to_le_bytes());
    bytes[8..12].copy_from_slice(&type_offset.to_le_bytes());
    bytes[12..16].copy_from_slice(&type_len.to_le_bytes());
    bytes[16..20].copy_from_slice(&string_offset.to_le_bytes());
    bytes[20..24].copy_from_slice(&string_len.to_le_bytes());
    bytes
}
