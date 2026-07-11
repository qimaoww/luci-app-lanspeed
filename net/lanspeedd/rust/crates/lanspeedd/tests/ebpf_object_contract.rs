use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

use aya_obj::{generated::bpf_map_type, obj::ProgramSection, Object};
use lanspeed_common::{
    CLIENTS_MAP_NAME, EGRESS_EARLY_PROGRAM_NAME, EGRESS_PROGRAM_NAME, INGRESS_EARLY_PROGRAM_NAME,
    INGRESS_PROGRAM_NAME, MAX_CLIENTS, MAX_CONN_TUPLES, SEEN_CONNS_MAP_NAME,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

fn object_path() -> PathBuf {
    env::var_os("LANSPEED_EBPF_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/bpfel-unknown-none/release/lanspeed-ebpf")
        })
}

fn object_bytes() -> Vec<u8> {
    let path = object_path();
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}; build lanspeed-ebpf first",
            path.display()
        )
    })
}

fn fallback_object_bytes() -> Vec<u8> {
    let path = env::var_os("LANSPEED_EBPF_FALLBACK_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/bpfel-unknown-none/release/lanspeed-ebpf-fallback")
        });
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}; build both lanspeed eBPF objects first",
            path.display()
        )
    })
}

#[test]
fn production_object_has_exact_maps_programs_and_license() {
    let bytes = object_bytes();
    let object = Object::parse(&bytes).expect("Aya must parse the eBPF object");

    assert_eq!(object.license.to_bytes_with_nul(), b"GPL\0");

    let map_names = object
        .maps
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        map_names,
        BTreeSet::from([CLIENTS_MAP_NAME, SEEN_CONNS_MAP_NAME])
    );

    let clients = &object.maps[CLIENTS_MAP_NAME];
    assert_eq!(
        clients.map_type(),
        bpf_map_type::BPF_MAP_TYPE_LRU_HASH as u32
    );
    assert_eq!(clients.key_size(), 16);
    assert_eq!(clients.value_size(), 32);
    assert_eq!(clients.max_entries(), MAX_CLIENTS);

    let seen = &object.maps[SEEN_CONNS_MAP_NAME];
    assert_eq!(seen.map_type(), bpf_map_type::BPF_MAP_TYPE_LRU_HASH as u32);
    assert_eq!(seen.key_size(), 28);
    assert_eq!(seen.value_size(), 1);
    assert_eq!(seen.max_entries(), MAX_CONN_TUPLES);

    let expected = BTreeSet::from([
        INGRESS_PROGRAM_NAME,
        EGRESS_PROGRAM_NAME,
        INGRESS_EARLY_PROGRAM_NAME,
        EGRESS_EARLY_PROGRAM_NAME,
    ]);
    let program_names = object
        .programs
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(program_names, expected);
    for program in object.programs.values() {
        assert!(matches!(program.section, ProgramSection::SchedClassifier));
    }
}

#[test]
fn production_object_keeps_conntrack_kfunc_btf_relocations() {
    let bytes = object_bytes();
    let elf = object::File::parse(bytes.as_slice()).expect("object crate must parse eBPF ELF");

    assert!(elf.section_by_name(".BTF").is_some(), "missing .BTF");
    assert!(
        elf.section_by_name(".BTF.ext").is_some(),
        "missing .BTF.ext"
    );

    let undefined = elf
        .symbols()
        .filter(|symbol| symbol.is_undefined())
        .filter_map(|symbol| symbol.name().ok())
        .collect::<BTreeSet<_>>();
    assert!(undefined.contains("bpf_skb_ct_lookup"));
    assert!(undefined.contains("bpf_ct_release"));

    let mut relocated_kfuncs = BTreeSet::new();
    for section in elf.sections() {
        for (_, relocation) in section.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let symbol = elf
                .symbol_by_index(index)
                .expect("relocation symbol must exist");
            if let Ok(name) = symbol.name() {
                if name == "bpf_skb_ct_lookup" || name == "bpf_ct_release" {
                    relocated_kfuncs.insert(name);
                }
            }
        }
    }
    assert_eq!(
        relocated_kfuncs,
        BTreeSet::from(["bpf_ct_release", "bpf_skb_ct_lookup"])
    );
}

#[test]
fn fallback_object_preserves_abi_without_kfunc_relocations() {
    let bytes = fallback_object_bytes();
    let parsed = Object::parse(&bytes).expect("Aya must parse the fallback object");

    assert_eq!(parsed.license.to_bytes_with_nul(), b"GPL\0");
    assert_eq!(
        parsed
            .maps
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([CLIENTS_MAP_NAME, SEEN_CONNS_MAP_NAME])
    );
    assert_eq!(
        parsed
            .programs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            INGRESS_PROGRAM_NAME,
            EGRESS_PROGRAM_NAME,
            INGRESS_EARLY_PROGRAM_NAME,
            EGRESS_EARLY_PROGRAM_NAME,
        ])
    );

    let elf = object::File::parse(bytes.as_slice()).expect("object crate must parse fallback ELF");
    assert!(elf.section_by_name(".BTF").is_some(), "missing .BTF");
    assert!(
        elf.section_by_name(".BTF.ext").is_some(),
        "missing .BTF.ext"
    );
    let undefined = elf
        .symbols()
        .filter(|symbol| symbol.is_undefined())
        .filter_map(|symbol| symbol.name().ok())
        .collect::<BTreeSet<_>>();
    assert!(!undefined.contains("bpf_skb_ct_lookup"));
    assert!(!undefined.contains("bpf_ct_release"));
}

#[test]
fn classifier_guards_short_frames_before_ethernet_load() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../lanspeed-ebpf/src/account.rs"),
    )
    .unwrap();
    let guard = source
        .find("if frame_len < ETHERNET_HEADER_LEN as u32")
        .expect("classifier must reject short frames before loading Ethernet bytes");
    let load = source
        .find("ctx.load_bytes(0, &mut ethernet)")
        .expect("classifier must load the Ethernet header");
    assert!(guard < load, "short-frame guard must precede Ethernet load");
}

#[test]
fn conntrack_prefix_load_uses_the_guarded_nonzero_frame_length() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../lanspeed-ebpf/src/account.rs"),
    )
    .unwrap();
    assert!(source.contains("let frame_len = ctx.len();"));
    assert!(source.contains("frame_len.min(PACKET_PREFIX_LEN as u32)"));
    assert!(source.contains("bpf_skb_load_bytes("));
}
