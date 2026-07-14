use aya::maps::MapError;
use aya_obj::btf::{Btf, BtfKind};
use aya_obj::generated::{bpf_attr, bpf_btf_info, bpf_cmd};
use object::{
    Object as _, ObjectSection as _, ObjectSymbol as _, RelocationFlags, RelocationTarget,
};
use std::{
    fs, io,
    os::fd::{FromRawFd, OwnedFd},
};

#[cfg(any(feature = "openwrt", test))]
mod clock;
pub mod collectors;
pub mod config;
pub mod connection_details;
pub mod connections;
pub mod daemon;
pub mod error;
pub mod history;
pub mod identity;
pub mod interfaces;
pub mod model;
pub mod policy;
pub mod probe;
#[cfg(feature = "openwrt")]
pub mod production;
#[cfg(any(feature = "openwrt", test))]
mod production_evidence;
pub mod rate;
pub mod state;
pub mod ubus;

pub const fn is_fresh(now_ms: u64, sample_ms: u64, limit_ms: u64) -> bool {
    sample_ms <= now_ms && now_ms - sample_ms <= limit_ms
}

pub fn counter_value(result: Result<u64, MapError>) -> Result<u64, MapError> {
    match result {
        Ok(value) => Ok(value),
        Err(MapError::KeyNotFound) => Ok(0),
        Err(error) => Err(error),
    }
}

const CONNTRACK_KFUNCS: [&str; 2] = ["bpf_skb_ct_lookup", "bpf_ct_release"];
const BPF_PSEUDO_KFUNC_CALL: u8 = 2;
const KNOWN_KFUNC_METADATA_ERROR: &str =
    "release kernel function bpf_skb_ct_lookup expects refcounted PTR_TO_BTF_ID";

pub fn is_known_kfunc_metadata_incompatibility(verifier_log: &str) -> bool {
    verifier_log.contains(KNOWN_KFUNC_METADATA_ERROR)
}

#[derive(Debug, Eq, PartialEq)]
pub struct FallbackLoad<T, E> {
    pub value: T,
    pub primary_error: Option<E>,
}

pub fn load_with_fallback<T, E, P, F, C>(
    primary: P,
    fallback: F,
    is_known_incompatibility: C,
) -> Result<FallbackLoad<T, E>, E>
where
    P: FnOnce() -> Result<T, E>,
    F: FnOnce() -> Result<T, E>,
    C: FnOnce(&E) -> bool,
{
    match primary() {
        Ok(value) => Ok(FallbackLoad {
            value,
            primary_error: None,
        }),
        Err(error) if is_known_incompatibility(&error) => fallback().map(|value| FallbackLoad {
            value,
            primary_error: Some(error),
        }),
        Err(error) => Err(error),
    }
}

pub fn patch_conntrack_kfunc_calls(bytes: &mut [u8]) -> Result<Vec<OwnedFd>, KfuncPatchError> {
    let base_bytes = fs::read("/sys/kernel/btf/vmlinux").map_err(KfuncPatchError::Io)?;
    let base =
        Btf::parse(&base_bytes, object::Endianness::Little).map_err(KfuncPatchError::KernelBtf)?;
    let base_targets = CONNTRACK_KFUNCS.map(|name| {
        base.id_by_type_name_kind(name, BtfKind::Func)
            .map(|type_id| KfuncTarget {
                type_id,
                btf_fd_index: 0,
            })
    });
    if base_targets.iter().all(Result::is_ok) {
        patch_conntrack_kfunc_calls_with(bytes, |name| {
            let index = CONNTRACK_KFUNCS
                .iter()
                .position(|candidate| *candidate == name)
                .unwrap();
            base_targets[index]
                .as_ref()
                .copied()
                .map_err(ToString::to_string)
        })?;
        return Ok(Vec::new());
    }

    let module_name = "nf_conntrack";
    let module_fd = kernel_btf_fd_by_name(module_name)?;
    let split_bytes =
        fs::read(format!("/sys/kernel/btf/{module_name}")).map_err(KfuncPatchError::Io)?;
    let merged = merge_split_btf(&base_bytes, &split_bytes)?;
    let module =
        Btf::parse(&merged, object::Endianness::Little).map_err(KfuncPatchError::KernelBtf)?;
    patch_conntrack_kfunc_calls_with(bytes, |name| {
        module
            .id_by_type_name_kind(name, BtfKind::Func)
            .map(|type_id| KfuncTarget {
                type_id,
                btf_fd_index: 1,
            })
            .map_err(|error| error.to_string())
    })?;
    Ok(vec![module_fd])
}

fn kernel_btf_fd_by_name(name: &str) -> Result<OwnedFd, KfuncPatchError> {
    let mut id = 0u32;
    loop {
        let mut next_attr = unsafe { core::mem::zeroed::<bpf_attr>() };
        next_attr.__bindgen_anon_6.__bindgen_anon_1.start_id = id;
        bpf_syscall(bpf_cmd::BPF_BTF_GET_NEXT_ID, &mut next_attr)?;
        id = unsafe { next_attr.__bindgen_anon_6.next_id };

        if let Some(fd) = select_kernel_btf_candidate(name, read_kernel_btf_candidate(id))
            .map_err(KfuncPatchError::Io)?
        {
            return Ok(fd);
        }
    }
}

#[doc(hidden)]
pub struct KernelBtfCandidate {
    pub fd: OwnedFd,
    pub kernel_btf: bool,
    pub name: String,
}

#[doc(hidden)]
pub fn select_kernel_btf_candidate(
    expected_name: &str,
    candidate: io::Result<KernelBtfCandidate>,
) -> io::Result<Option<OwnedFd>> {
    match candidate {
        Ok(candidate) if candidate.kernel_btf && candidate.name == expected_name => {
            Ok(Some(candidate.fd))
        }
        Ok(_) => Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_kernel_btf_candidate(id: u32) -> io::Result<KernelBtfCandidate> {
    let mut fd_attr = unsafe { core::mem::zeroed::<bpf_attr>() };
    fd_attr.__bindgen_anon_6.__bindgen_anon_1.btf_id = id;
    let raw_fd = raw_bpf_syscall(bpf_cmd::BPF_BTF_GET_FD_BY_ID, &mut fd_attr)? as i32;
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut name_buf = [0u8; 64];
    let mut info = unsafe { core::mem::zeroed::<bpf_btf_info>() };
    info.name = name_buf.as_mut_ptr() as u64;
    info.name_len = name_buf.len() as u32;
    let mut info_attr = unsafe { core::mem::zeroed::<bpf_attr>() };
    info_attr.info.bpf_fd = raw_fd as u32;
    info_attr.info.info_len = size_of::<bpf_btf_info>() as u32;
    info_attr.info.info = (&mut info as *mut bpf_btf_info) as u64;
    raw_bpf_syscall(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut info_attr)?;
    let name = name_buf
        .split(|byte| *byte == 0)
        .next()
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .unwrap_or_default()
        .to_owned();
    Ok(KernelBtfCandidate {
        fd,
        kernel_btf: info.kernel_btf != 0,
        name,
    })
}

fn bpf_syscall(cmd: bpf_cmd, attr: &mut bpf_attr) -> Result<i64, KfuncPatchError> {
    raw_bpf_syscall(cmd, attr).map_err(KfuncPatchError::Io)
}

fn raw_bpf_syscall(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    let result = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size_of::<bpf_attr>()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn patch_conntrack_kfunc_calls_with<F, E>(
    bytes: &mut [u8],
    mut resolve: F,
) -> Result<(), KfuncPatchError>
where
    F: FnMut(&str) -> Result<KfuncTarget, E>,
    E: std::fmt::Display,
{
    let patches = {
        let elf = object::File::parse(&*bytes).map_err(KfuncPatchError::Object)?;
        let mut patches = Vec::new();
        for section in elf.sections() {
            let Some((file_offset, _)) = section.file_range() else {
                continue;
            };
            for (offset, relocation) in section.relocations() {
                let RelocationTarget::Symbol(index) = relocation.target() else {
                    continue;
                };
                let symbol = elf
                    .symbol_by_index(index)
                    .map_err(KfuncPatchError::Object)?;
                let Ok(name) = symbol.name() else { continue };
                if CONNTRACK_KFUNCS.contains(&name) {
                    let offset = usize::try_from(file_offset + offset)
                        .map_err(|_| KfuncPatchError::InvalidInstruction(name.to_owned()))?;
                    if !matches!(relocation.flags(), RelocationFlags::Elf { r_type: 10 }) {
                        return Err(KfuncPatchError::InvalidInstruction(name.to_owned()));
                    }
                    let instruction = bytes
                        .get(offset..offset + 8)
                        .ok_or_else(|| KfuncPatchError::InvalidInstruction(name.to_owned()))?;
                    if instruction[0] != 0x85
                        || instruction[1] != 0x10
                        || instruction[2..4] != 0i16.to_le_bytes()
                        || instruction[4..8] != (-1i32).to_le_bytes()
                    {
                        return Err(KfuncPatchError::InvalidInstruction(name.to_owned()));
                    }
                    patches.push((offset, name.to_owned()));
                }
            }
        }
        patches
    };

    for name in CONNTRACK_KFUNCS {
        if !patches.iter().any(|(_, found)| found == name) {
            return Err(KfuncPatchError::MissingRelocation(name.to_owned()));
        }
    }

    let resolved = patches
        .into_iter()
        .map(|(offset, name)| {
            resolve(&name)
                .map(|target| (offset, name.clone(), target))
                .map_err(|error| KfuncPatchError::Resolve {
                    name,
                    reason: error.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (offset, name, target) in resolved {
        let instruction = bytes
            .get_mut(offset..offset + 8)
            .ok_or_else(|| KfuncPatchError::InvalidInstruction(name.clone()))?;
        instruction[1] = (instruction[1] & 0x0f) | (BPF_PSEUDO_KFUNC_CALL << 4);
        instruction[2..4].copy_from_slice(&target.btf_fd_index.to_le_bytes());
        instruction[4..8].copy_from_slice(&(target.type_id as i32).to_le_bytes());
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KfuncTarget {
    pub type_id: u32,
    pub btf_fd_index: i16,
}

pub fn merge_split_btf(base: &[u8], split: &[u8]) -> Result<Vec<u8>, KfuncPatchError> {
    let base_header = btf_header(base)?;
    let split_header = btf_header(split)?;
    let base_types = btf_section(base, base_header.0, base_header.1, base_header.2)?;
    let base_strings = btf_section(base, base_header.0, base_header.3, base_header.4)?;
    let split_types = btf_section(split, split_header.0, split_header.1, split_header.2)?;
    let split_strings = btf_section(split, split_header.0, split_header.3, split_header.4)?;

    let type_len = checked_btf_len(base_types.len(), split_types.len())?;
    let string_len = checked_btf_len(base_strings.len(), split_strings.len())?;
    let base_prefix = base
        .get(..base_header.0)
        .ok_or_else(|| KfuncPatchError::InvalidBtf("truncated BTF header".into()))?;
    let merged_len =
        checked_total_btf_len(base_prefix.len(), type_len as usize, string_len as usize)?;
    let mut merged = Vec::new();
    merged
        .try_reserve_exact(merged_len)
        .map_err(|_| KfuncPatchError::InvalidBtf("merged BTF is too large".into()))?;
    merged.extend_from_slice(base_prefix);
    merged[8..12].copy_from_slice(&0u32.to_le_bytes());
    merged[12..16].copy_from_slice(&type_len.to_le_bytes());
    merged[16..20].copy_from_slice(&type_len.to_le_bytes());
    merged[20..24].copy_from_slice(&string_len.to_le_bytes());
    merged.extend_from_slice(base_types);
    merged.extend_from_slice(split_types);
    merged.extend_from_slice(base_strings);
    merged.extend_from_slice(split_strings);
    Ok(merged)
}

fn btf_header(bytes: &[u8]) -> Result<(usize, usize, usize, usize, usize), KfuncPatchError> {
    if bytes.len() < 24 || u16::from_le_bytes([bytes[0], bytes[1]]) != 0xeb9f {
        return Err(KfuncPatchError::InvalidBtf("invalid BTF header".into()));
    }
    let read = |offset| -> Result<usize, KfuncPatchError> {
        let value = bytes
            .get(offset..offset + 4)
            .ok_or_else(|| KfuncPatchError::InvalidBtf("truncated BTF header".into()))?;
        usize::try_from(u32::from_le_bytes(value.try_into().map_err(|_| {
            KfuncPatchError::InvalidBtf("invalid BTF header field".into())
        })?))
        .map_err(|_| KfuncPatchError::InvalidBtf("BTF header field is too large".into()))
    };
    let header_len = read(4)?;
    if !(24..=bytes.len()).contains(&header_len) {
        return Err(KfuncPatchError::InvalidBtf(
            "invalid BTF header length".into(),
        ));
    }
    Ok((header_len, read(8)?, read(12)?, read(16)?, read(20)?))
}

fn btf_section(
    bytes: &[u8],
    header_len: usize,
    offset: usize,
    len: usize,
) -> Result<&[u8], KfuncPatchError> {
    let start = header_len
        .checked_add(offset)
        .ok_or_else(|| KfuncPatchError::InvalidBtf("BTF section offset overflow".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| KfuncPatchError::InvalidBtf("BTF section length overflow".into()))?;
    bytes
        .get(start..end)
        .ok_or_else(|| KfuncPatchError::InvalidBtf("truncated BTF section".into()))
}

fn checked_btf_len(left: usize, right: usize) -> Result<u32, KfuncPatchError> {
    let combined = left
        .checked_add(right)
        .ok_or_else(|| KfuncPatchError::InvalidBtf("combined BTF length overflow".into()))?;
    u32::try_from(combined)
        .map_err(|_| KfuncPatchError::InvalidBtf("combined BTF length exceeds u32".into()))
}

fn checked_total_btf_len(
    header_len: usize,
    type_len: usize,
    string_len: usize,
) -> Result<usize, KfuncPatchError> {
    header_len
        .checked_add(type_len)
        .and_then(|length| length.checked_add(string_len))
        .ok_or_else(|| KfuncPatchError::InvalidBtf("merged BTF length overflow".into()))
}

#[derive(Debug)]
pub enum KfuncPatchError {
    KernelBtf(aya_obj::btf::BtfError),
    Object(object::Error),
    MissingRelocation(String),
    InvalidInstruction(String),
    Resolve { name: String, reason: String },
    InvalidBtf(String),
    Io(io::Error),
}

impl KfuncPatchError {
    pub fn is_kernel_incompatibility(&self) -> bool {
        match self {
            Self::KernelBtf(_) | Self::Resolve { .. } | Self::InvalidBtf(_) => true,
            Self::Io(error) => matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::ENOSYS | libc::EOPNOTSUPP)
            ),
            Self::Object(_) | Self::MissingRelocation(_) | Self::InvalidInstruction(_) => false,
        }
    }
}

impl std::fmt::Display for KfuncPatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KernelBtf(error) => write!(formatter, "failed to read kernel BTF: {error}"),
            Self::Object(error) => write!(formatter, "failed to parse eBPF object: {error}"),
            Self::MissingRelocation(name) => {
                write!(formatter, "missing kfunc relocation for {name}")
            }
            Self::InvalidInstruction(name) => {
                write!(formatter, "invalid kfunc call instruction for {name}")
            }
            Self::Resolve { name, reason } => {
                write!(
                    formatter,
                    "kernel does not provide required kfunc {name}: {reason}"
                )
            }
            Self::InvalidBtf(reason) => write!(formatter, "invalid split BTF: {reason}"),
            Self::Io(error) => write!(formatter, "BPF/BTF I/O failed: {error}"),
        }
    }
}

impl std::error::Error for KfuncPatchError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_btf_lengths_must_fit_the_wire_u32() {
        assert!(matches!(
            checked_btf_len(u32::MAX as usize, 1),
            Err(KfuncPatchError::InvalidBtf(_))
        ));
        assert!(matches!(
            checked_total_btf_len(usize::MAX, 1, 0),
            Err(KfuncPatchError::InvalidBtf(_))
        ));
    }
}
