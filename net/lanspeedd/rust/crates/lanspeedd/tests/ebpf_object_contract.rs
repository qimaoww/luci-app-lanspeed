use std::{
    collections::{BTreeSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
};

use aya_obj::{generated::bpf_map_type, obj::ProgramSection, Object};
use lanspeed_common::{
    CLIENTS_MAP_NAME, EGRESS_EARLY_PROGRAM_NAME, EGRESS_PROGRAM_NAME, INGRESS_EARLY_PROGRAM_NAME,
    INGRESS_PROGRAM_NAME, MAX_CLIENTS, MAX_CONN_TUPLES, SEEN_CONNS_MAP_NAME,
};
use object::{
    Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget, SectionIndex,
    SectionKind, SymbolKind,
};

const PACKET_SCRATCH_MAP_NAME: &str = "lanspeed_packet_prefix";
const CONNTRACK_SCRATCH_MAP_NAME: &str = "lanspeed_conntrack_scratch";

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

fn fallback_object_path() -> PathBuf {
    env::var_os("LANSPEED_EBPF_FALLBACK_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/bpfel-unknown-none/release/lanspeed-ebpf-fallback")
        })
}

fn fallback_object_bytes() -> Vec<u8> {
    let path = fallback_object_path();
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}; build both lanspeed eBPF objects first",
            path.display()
        )
    })
}

#[test]
fn objects_are_fresh_for_the_accounting_sources() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sources = [
        workspace.join("crates/lanspeed-common/src/accounting.rs"),
        workspace.join("crates/lanspeed-common/src/packet.rs"),
        workspace.join("crates/lanspeed-ebpf/src/account.rs"),
        workspace.join("crates/lanspeed-ebpf/src/conntrack.rs"),
    ];

    for object in [object_path(), fallback_object_path()] {
        let object_time = fs::metadata(&object)
            .unwrap_or_else(|error| panic!("failed to stat {}: {error}", object.display()))
            .modified()
            .expect("object modification time must be available");
        for source in &sources {
            let source_time = fs::metadata(source)
                .unwrap_or_else(|error| panic!("failed to stat {}: {error}", source.display()))
                .modified()
                .expect("source modification time must be available");
            assert!(
                object_time >= source_time,
                "{} is older than {}; rebuild both eBPF variants before running this contract",
                object.display(),
                source.display()
            );
        }
    }
}

#[test]
fn compiled_objects_read_wire_len_and_gso_segs() {
    for bytes in [object_bytes(), fallback_object_bytes()] {
        let elf = object::File::parse(bytes.as_slice()).expect("object crate must parse eBPF ELF");
        let mut offsets = BTreeSet::new();
        for section in elf
            .sections()
            .filter(|section| section.kind() == SectionKind::Text)
        {
            let data = section.data().expect("eBPF text section must be readable");
            for instruction in data.chunks_exact(8) {
                if instruction[0] == 0x61 {
                    offsets.insert(i16::from_le_bytes([instruction[2], instruction[3]]));
                }
            }
        }
        assert!(
            offsets.contains(&0xa0),
            "compiled object does not read wire_len"
        );
        assert!(
            offsets.contains(&0xa4),
            "compiled object does not read gso_segs"
        );
    }
}

#[test]
fn compiled_accounting_entry_does_not_zero_the_full_prefix() {
    for bytes in [object_bytes(), fallback_object_bytes()] {
        let elf = object::File::parse(bytes.as_slice()).expect("object crate must parse eBPF ELF");
        let text = elf
            .section_by_name(".text")
            .expect("compiled eBPF object must contain .text");
        for (offset, relocation) in text.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let symbol = elf
                .symbol_by_index(index)
                .expect("relocation symbol must exist");
            if symbol.name().ok() == Some("memset") {
                assert!(
                    offset >= 0x100,
                    "account_frame entry calls memset at {offset:#x}; the ordinary packet path must not clear the 142-byte prefix"
                );
            }
        }
    }
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
        BTreeSet::from([
            CLIENTS_MAP_NAME,
            CONNTRACK_SCRATCH_MAP_NAME,
            PACKET_SCRATCH_MAP_NAME,
            SEEN_CONNS_MAP_NAME,
        ])
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

    let packet_scratch = &object.maps[PACKET_SCRATCH_MAP_NAME];
    assert_eq!(
        packet_scratch.map_type(),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32
    );
    assert_eq!(
        (packet_scratch.key_size(), packet_scratch.value_size()),
        (4, 160)
    );
    assert_eq!(packet_scratch.max_entries(), 1);

    let conntrack_scratch = &object.maps[CONNTRACK_SCRATCH_MAP_NAME];
    assert_eq!(
        conntrack_scratch.map_type(),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32
    );
    assert_eq!(
        (conntrack_scratch.key_size(), conntrack_scratch.value_size()),
        (4, 128)
    );
    assert_eq!(conntrack_scratch.max_entries(), 1);

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
    assert_eq!(
        undefined,
        BTreeSet::from(["bpf_ct_release", "bpf_skb_ct_lookup"])
    );

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
        BTreeSet::from([CLIENTS_MAP_NAME, PACKET_SCRATCH_MAP_NAME])
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
    let clients = &parsed.maps[CLIENTS_MAP_NAME];
    assert_eq!(
        clients.map_type(),
        bpf_map_type::BPF_MAP_TYPE_LRU_HASH as u32
    );
    assert_eq!((clients.key_size(), clients.value_size()), (16, 32));
    assert_eq!(clients.max_entries(), MAX_CLIENTS);
    let packet_scratch = &parsed.maps[PACKET_SCRATCH_MAP_NAME];
    assert_eq!(
        packet_scratch.map_type(),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32
    );
    assert_eq!(
        (packet_scratch.key_size(), packet_scratch.value_size()),
        (4, 160)
    );
    assert_eq!(packet_scratch.max_entries(), 1);
    assert!(!parsed.maps.contains_key(SEEN_CONNS_MAP_NAME));
    assert!(!parsed.maps.contains_key(CONNTRACK_SCRATCH_MAP_NAME));
    for program in parsed.programs.values() {
        assert!(matches!(program.section, ProgramSection::SchedClassifier));
    }

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
        .find("load_packet_prefix(&ctx, prefix_ptr, ETHERNET_HEADER_LEN as u32)")
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

fn maximum_function_stack(instructions: &[u8]) -> usize {
    const REGISTER_COUNT: usize = 11;
    const OVER_BUDGET_OFFSET: i32 = -513;

    assert_eq!(instructions.len() % 8, 0, "truncated eBPF instruction");
    let instruction_count = instructions.len() / 8;
    if instruction_count == 0 {
        return 0;
    }

    let mut states = vec![None; instruction_count];
    let mut initial = [None; REGISTER_COUNT];
    initial[10] = Some(0_i32);
    states[0] = Some(initial);
    let mut pending = VecDeque::from([0_usize]);
    let mut maximum = 0_usize;

    let merge = |target: usize,
                 incoming: [Option<i32>; REGISTER_COUNT],
                 states: &mut Vec<Option<[Option<i32>; REGISTER_COUNT]>>,
                 pending: &mut VecDeque<usize>| {
        if target >= states.len() {
            return;
        }
        let mut changed = false;
        if let Some(current) = &mut states[target] {
            for register in 0..REGISTER_COUNT {
                if let Some(offset) = incoming[register] {
                    if current[register].is_none_or(|known| offset < known) {
                        current[register] = Some(offset);
                        changed = true;
                    }
                }
            }
        } else {
            states[target] = Some(incoming);
            changed = true;
        }
        if changed {
            pending.push_back(target);
        }
    };

    while let Some(index) = pending.pop_front() {
        let instruction = &instructions[index * 8..index * 8 + 8];
        let opcode = instruction[0];
        let class = opcode & 0x07;
        let operation = opcode & 0xf0;
        let registers = instruction[1];
        let destination = usize::from(registers & 0x0f);
        let source = usize::from(registers >> 4);
        let offset = i32::from(i16::from_le_bytes([instruction[2], instruction[3]]));
        let immediate = i32::from_le_bytes(instruction[4..8].try_into().unwrap());
        let mut next = states[index].expect("queued instruction must have state");

        let memory_base = match class {
            0x01 => Some(source),
            0x02 | 0x03 => Some(destination),
            _ => None,
        };
        if let Some(base) = memory_base.and_then(|register| next[register]) {
            let address = base.saturating_add(offset);
            if address < 0 {
                maximum = maximum.max(address.unsigned_abs() as usize);
            }
        }

        let mut step = 1_usize;
        match class {
            0x00 if opcode == 0x18 => {
                next[destination] = None;
                step = 2;
            }
            0x00 | 0x01 => next[destination] = None,
            0x04 => {
                let register_source = opcode & 0x08 != 0;
                let stack_involved =
                    next[destination].is_some() || (register_source && next[source].is_some());
                next[destination] = stack_involved.then_some(OVER_BUDGET_OFFSET);
                if stack_involved {
                    maximum = maximum.max(OVER_BUDGET_OFFSET.unsigned_abs() as usize);
                }
            }
            0x07 => {
                let register_source = opcode & 0x08 != 0;
                match (operation, register_source) {
                    (0xb0, true) => next[destination] = next[source],
                    (0xb0, false) => next[destination] = None,
                    (0x00, false) => {
                        next[destination] = next[destination]
                            .map(|value| value.saturating_add(immediate).max(OVER_BUDGET_OFFSET));
                    }
                    (0x10, false) => {
                        next[destination] = next[destination]
                            .map(|value| value.saturating_sub(immediate).max(OVER_BUDGET_OFFSET));
                    }
                    _ => {
                        let stack_involved = next[destination].is_some()
                            || (register_source && next[source].is_some());
                        next[destination] = stack_involved.then_some(OVER_BUDGET_OFFSET);
                    }
                }
                if let Some(address) = next[destination].filter(|address| *address < 0) {
                    maximum = maximum.max(address.unsigned_abs() as usize);
                }
            }
            0x05 | 0x06 if operation == 0x80 => {
                next[..=5].fill(None);
            }
            _ => {}
        }
        next[10] = Some(0);

        if matches!(class, 0x05 | 0x06) {
            match operation {
                0x90 => continue,
                0x00 => {
                    let target = (index as isize + 1 + offset as isize) as usize;
                    merge(target, next, &mut states, &mut pending);
                    continue;
                }
                0x80 => {}
                _ => {
                    let target = (index as isize + 1 + offset as isize) as usize;
                    merge(target, next, &mut states, &mut pending);
                }
            }
        }
        merge(index + step, next, &mut states, &mut pending);
    }

    maximum
}

enum PseudoCallRelocation {
    Defined(SectionIndex, usize),
    External(String),
    Unsupported,
}

fn supported_external_call(name: &str) -> bool {
    matches!(name, "bpf_skb_ct_lookup" | "bpf_ct_release")
}

fn pseudo_call_offsets(instructions: &[u8]) -> Vec<usize> {
    assert_eq!(instructions.len() % 8, 0, "truncated eBPF instruction");
    let mut calls = Vec::new();
    let mut offset = 0_usize;
    while offset < instructions.len() {
        let instruction = &instructions[offset..offset + 8];
        if instruction[0] == 0x85 && instruction[1] >> 4 == 1 {
            calls.push(offset);
        }
        let width = if instruction[0] == 0x18 { 16 } else { 8 };
        assert!(
            offset + width <= instructions.len(),
            "truncated lddw instruction"
        );
        offset += width;
    }
    calls
}

#[test]
fn pseudo_call_scan_skips_lddw_second_slot() {
    let instructions = [0x18, 0x01, 0, 0, 0, 0, 0, 0, 0x85, 0x10, 0, 0, 0, 0, 0, 0];
    assert!(pseudo_call_offsets(&instructions).is_empty());
}

#[test]
fn external_call_allowlist_rejects_unexpected_symbols() {
    assert!(supported_external_call("bpf_skb_ct_lookup"));
    assert!(supported_external_call("bpf_ct_release"));
    assert!(!supported_external_call("unlinked_bpf_subprogram"));
}

fn object_stack_profile(bytes: &[u8]) -> (Vec<String>, Vec<usize>, Vec<Vec<usize>>) {
    struct FunctionRange {
        name: String,
        section: SectionIndex,
        start: usize,
        end: usize,
    }

    let elf = object::File::parse(bytes).expect("object crate must parse eBPF ELF");
    let mut functions = elf
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter_map(|symbol| {
            let section = symbol.section_index()?;
            let text = elf.section_by_index(section).ok()?;
            (text.kind() == SectionKind::Text).then(|| {
                let start = usize::try_from(symbol.address()).expect("function offset fits usize");
                let size = usize::try_from(symbol.size()).expect("function size fits usize");
                let end = start
                    .checked_add(size)
                    .expect("function range does not wrap");
                assert!(
                    end <= text.size() as usize,
                    "function exceeds its executable section"
                );
                FunctionRange {
                    name: symbol.name().unwrap_or("<unnamed>").to_owned(),
                    section,
                    start,
                    end,
                }
            })
        })
        .collect::<Vec<_>>();
    functions.sort_by_key(|function| (function.section.0, function.start));
    functions.dedup_by_key(|function| (function.section.0, function.start, function.end));
    assert!(!functions.is_empty(), "eBPF object has no function symbols");

    let names = functions
        .iter()
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();
    let frame_sizes = functions
        .iter()
        .map(|function| {
            let section = elf
                .section_by_index(function.section)
                .expect("function section must exist");
            let data = section.data().expect("eBPF text section must be readable");
            maximum_function_stack(&data[function.start..function.end])
        })
        .collect::<Vec<_>>();

    let calls = functions
        .iter()
        .map(|function| {
            let section = elf
                .section_by_index(function.section)
                .expect("function section must exist");
            let data = section.data().expect("eBPF text section must be readable");
            let relocations = section
                .relocations()
                .map(|(offset, relocation)| {
                    let target = match relocation.target() {
                        RelocationTarget::Symbol(index) => {
                            let symbol = elf
                                .symbol_by_index(index)
                                .expect("relocation symbol must exist");
                            symbol.section_index().map_or_else(
                                || {
                                    PseudoCallRelocation::External(
                                        symbol.name().unwrap_or("<unnamed>").to_owned(),
                                    )
                                },
                                |target_section| {
                                let address = i128::from(symbol.address())
                                    .checked_add(i128::from(relocation.addend()))
                                    .expect("relocation address does not overflow");
                                    PseudoCallRelocation::Defined(
                                        target_section,
                                        usize::try_from(address)
                                            .expect("relocation address fits usize"),
                                    )
                                },
                            )
                        }
                        RelocationTarget::Section(target_section) => {
                            usize::try_from(relocation.addend())
                                .map(|address| {
                                    PseudoCallRelocation::Defined(target_section, address)
                                })
                                .unwrap_or(PseudoCallRelocation::Unsupported)
                        }
                        _ => PseudoCallRelocation::Unsupported,
                    };
                    (offset as usize, target)
                })
                .collect::<Vec<_>>();
            let mut callees = BTreeSet::new();

            for relative_offset in pseudo_call_offsets(&data[function.start..function.end]) {
                let instruction_offset = function.start + relative_offset;
                let instruction = &data[instruction_offset..instruction_offset + 8];

                let relocated = relocations
                    .iter()
                    .find(|(offset, _)| *offset == instruction_offset)
                    .map(|(_, target)| target);
                let (target_section, target_address) = match relocated {
                    Some(PseudoCallRelocation::Defined(section, address)) => (*section, *address),
                    Some(PseudoCallRelocation::External(name)) => {
                        assert!(
                            supported_external_call(name),
                            "unexpected unresolved BPF pseudo-call {name}"
                        );
                        continue;
                    }
                    Some(PseudoCallRelocation::Unsupported) => {
                        panic!("unsupported BPF pseudo-call relocation")
                    }
                    None => {
                        let immediate =
                            i32::from_le_bytes(instruction[4..8].try_into().unwrap()) as isize;
                        let address = instruction_offset as isize + 8 + immediate * 8;
                        assert!(address >= 0, "BPF call target precedes section start");
                        (function.section, address as usize)
                    }
                };
                let callee = functions
                    .iter()
                    .position(|candidate| {
                        candidate.section == target_section && candidate.start == target_address
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "unresolved BPF-to-BPF call target section {} offset {target_address:#x}",
                            target_section.0
                        )
                    });
                callees.insert(callee);
            }

            callees.into_iter().collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    (names, frame_sizes, calls)
}

#[test]
fn stack_frame_accounts_for_derived_frame_pointer() {
    let mut instructions = vec![0xbf, 0xa1, 0, 0, 0, 0, 0, 0];
    instructions.extend_from_slice(&[0x07, 0x01, 0, 0]);
    instructions.extend_from_slice(&(-288_i32).to_le_bytes());

    assert_eq!(maximum_function_stack(&instructions), 288);
}

#[test]
fn stack_frame_fails_closed_on_unmodelled_pointer_arithmetic() {
    let mut instructions = vec![0xbf, 0xa1, 0, 0, 0, 0, 0, 0];
    instructions.extend_from_slice(&[0xb7, 0x02, 0, 0]);
    instructions.extend_from_slice(&(-400_i32).to_le_bytes());
    instructions.extend_from_slice(&[0x0f, 0x21, 0, 0, 0, 0, 0, 0]);
    instructions.extend_from_slice(&[0x72, 0x01, 0, 0, 0, 0, 0, 0]);

    assert!(maximum_function_stack(&instructions) > 512);
}

fn maximum_call_chain_stack(frame_sizes: &[usize], calls: &[Vec<usize>]) -> usize {
    assert_eq!(frame_sizes.len(), calls.len());

    fn depth(
        function: usize,
        frame_sizes: &[usize],
        calls: &[Vec<usize>],
        visiting: &mut [bool],
        memo: &mut [Option<usize>],
    ) -> usize {
        if let Some(depth) = memo[function] {
            return depth;
        }
        assert!(
            !visiting[function],
            "recursive BPF-to-BPF call graph is not verifier-compatible"
        );
        visiting[function] = true;
        let child_depth = calls[function]
            .iter()
            .map(|&callee| {
                assert!(callee < frame_sizes.len(), "invalid BPF call target");
                depth(callee, frame_sizes, calls, visiting, memo)
            })
            .max()
            .unwrap_or(0);
        visiting[function] = false;
        let rounded_frame = frame_sizes[function].max(1).div_ceil(32) * 32;
        let result = rounded_frame + child_depth;
        memo[function] = Some(result);
        result
    }

    let mut visiting = vec![false; frame_sizes.len()];
    let mut memo = vec![None; frame_sizes.len()];
    (0..frame_sizes.len())
        .map(|function| depth(function, frame_sizes, calls, &mut visiting, &mut memo))
        .max()
        .unwrap_or(0)
}

#[test]
fn stack_budget_accumulates_bpf_to_bpf_call_frames() {
    let stack = maximum_call_chain_stack(&[288, 288], &[vec![1], Vec::new()]);
    assert_eq!(stack, 576);
}

#[test]
fn stack_budget_rounds_each_frame_like_kernel_verifier() {
    let stack = maximum_call_chain_stack(&[1, 481], &[vec![1], Vec::new()]);
    assert_eq!(stack, 544);
}

#[test]
fn stack_budget_conservatively_charges_zero_sized_frames() {
    let stack = maximum_call_chain_stack(&[0, 481], &[vec![1], Vec::new()]);
    assert_eq!(stack, 544);
}

#[test]
fn production_stack_profile_resolves_bpf_to_bpf_calls() {
    let (names, frame_sizes, calls) = object_stack_profile(&object_bytes());
    assert!(frame_sizes.len() >= 5, "missing compiled BPF functions");
    for program in [
        INGRESS_PROGRAM_NAME,
        EGRESS_PROGRAM_NAME,
        INGRESS_EARLY_PROGRAM_NAME,
        EGRESS_EARLY_PROGRAM_NAME,
    ] {
        let caller = names
            .iter()
            .position(|name| name == program)
            .unwrap_or_else(|| panic!("missing classifier function {program}"));
        assert!(
            calls[caller]
                .iter()
                .any(|&callee| names[callee].contains("account_frame")),
            "{program} does not call account_frame"
        );
    }
}

#[test]
fn production_object_stays_within_kernel_stack_budget() {
    let (_, frame_sizes, calls) = object_stack_profile(&object_bytes());
    let stack = maximum_call_chain_stack(&frame_sizes, &calls);
    assert!(
        stack <= 512,
        "kfunc object uses {stack} bytes across its deepest BPF-to-BPF call chain; the kernel limit is 512"
    );
}

#[test]
fn packet_prefix_covers_maximum_ipv4_and_tcp_headers() {
    let source = include_str!("../../lanspeed-ebpf/src/account.rs");
    assert!(
        source.contains("const PACKET_PREFIX_LEN: usize = 142;"),
        "Ethernet(14)+two VLAN tags(8)+IPv4(60)+TCP(60) requires a 142-byte prefix"
    );
}

#[test]
fn classifier_applies_gso_metadata_to_every_counter_update_path() {
    let source = include_str!("../../lanspeed-ebpf/src/account.rs");
    let compact_source = source.split_whitespace().collect::<String>();

    assert!(source.contains("(*skb).wire_len"));
    assert!(source.contains("(*skb).gso_segs"));
    assert!(source.contains("gro_repeated_header_len"));
    assert!(compact_source.contains("direction==DIR_TX&&gso_segs>1"));
    assert!(compact_source
        .contains("tc_frame_accounting(direction,frame_len,wire_len,gso_segs,ingress_header_len"));
    assert!(source.contains("bytes: accounting.bytes"));
    assert!(source.contains("packets: accounting.packets"));
    assert_eq!(
        source
            .matches("add_packet(counters, accounting.bytes, accounting.packets, now)")
            .count(),
        2,
        "both existing-entry paths must use the same normalized deltas"
    );
}
