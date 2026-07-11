use std::fs;

use aya_obj::btf::{Btf, BtfKind};
use lanspeedd::merge_split_btf;
use object::Endianness;

#[test]
fn merges_module_btf_with_vmlinux_type_and_string_bases() {
    let base_bytes = fs::read("/sys/kernel/btf/vmlinux").unwrap();
    let module_bytes = fs::read("/sys/kernel/btf/nf_conntrack").unwrap();
    let base = Btf::parse(&base_bytes, Endianness::Little).unwrap();
    assert!(base
        .id_by_type_name_kind("bpf_skb_ct_lookup", BtfKind::Func)
        .is_err());

    let merged = merge_split_btf(&base_bytes, &module_bytes).unwrap();
    let btf = Btf::parse(&merged, Endianness::Little).unwrap();
    let lookup = btf
        .id_by_type_name_kind("bpf_skb_ct_lookup", BtfKind::Func)
        .unwrap();
    let release = btf
        .id_by_type_name_kind("bpf_ct_release", BtfKind::Func)
        .unwrap();
    eprintln!("lookup={lookup} release={release}");
    assert!(lookup > 0);
    assert!(release > 0);
}
