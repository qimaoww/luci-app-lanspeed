#![no_std]

pub mod accounting;
pub mod packet;

pub const CLIENTS_MAP_NAME: &str = "lanspeed_clients";
pub const SEEN_CONNS_MAP_NAME: &str = "lanspeed_seen_conns";
pub const ECM_CLIENTS_MAP_NAME: &str = "lanspeed_ecm_clients";
pub const ECM_LAYOUT_MAP_NAME: &str = "lanspeed_ecm_layout";
pub const ECM_NSS_CONTEXT_MAP_NAME: &str = "lanspeed_ecm_nss_context";
pub const ECM_SOURCE_STATS_MAP_NAME: &str = "lanspeed_ecm_source_stats";

pub const INGRESS_PROGRAM_NAME: &str = "lanspeed_ingress";
pub const EGRESS_PROGRAM_NAME: &str = "lanspeed_egress";
pub const INGRESS_EARLY_PROGRAM_NAME: &str = "lanspeed_ingress_early";
pub const EGRESS_EARLY_PROGRAM_NAME: &str = "lanspeed_egress_early";
pub const ECM_UPDATE_PROGRAM_NAME: &str = "lanspeed_ecm_update";
pub const ECM_NSS_ENTER_PROGRAM_NAME: &str = "lanspeed_ecm_nss_enter";
pub const ECM_NSS_EXIT_PROGRAM_NAME: &str = "lanspeed_ecm_nss_exit";

pub const MAX_CLIENTS: u32 = 2048;
pub const MAX_CONN_TUPLES: u32 = 8192;
pub const MAX_ECM_NSS_CONTEXTS: u32 = 4096;

pub const DIR_TX: u8 = 1;
pub const DIR_RX: u8 = 2;

// Kept until the toolchain proof programs are replaced by the full data plane.
#[doc(hidden)]
pub const BYTE_COUNT_KEY: u32 = 0;
#[doc(hidden)]
pub const BYTE_COUNTS_MAP: &str = "BYTE_COUNTS";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct LanspeedKey {
    pub ifindex: u32,
    pub vlan_or_zone: u16,
    pub direction: u8,
    pub reserved: u8,
    pub mac: [u8; 6],
    pub padding: [u8; 2],
}

/// BPF counter value with an explicit eight-byte alignment on every target.
///
/// The alignment is part of the map ABI: userspace and 32-bit eBPF build hosts
/// must retain the same 32-byte layout as 64-bit targets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct LanspeedCounters {
    pub bytes: u64,
    pub packets: u64,
    pub last_seen: u64,
    pub tcp_conns: u32,
    pub udp_conns: u32,
}

/// Runtime-discovered ECM structure layout consumed by the kprobe program.
///
/// The Qualcomm ECM module is built out-of-tree and its private structure
/// offsets are not a stable ABI. Userspace resolves these three fields from
/// `/sys/kernel/btf/ecm` before attaching the program. Keeping the offsets in
/// a map avoids baking a firmware-specific layout into the eBPF object.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct EcmLayout {
    pub connection_node_offset: u32,
    pub connection_generation_offset: u32,
    pub node_address_offset: u32,
    pub pointer_size: u8,
    pub from_index: u8,
    pub to_index: u8,
    pub ready: u8,
}

/// ECM client-direction key ABI. Current eBPF objects set `connection` and
/// `generation` to zero to aggregate by MAC + direction. Userspace continues
/// accepting non-zero legacy per-connection keys during rolling upgrades.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct EcmKey {
    pub connection: u64,
    pub generation: u32,
    pub direction: u8,
    pub reserved: u8,
    pub mac: [u8; 6],
    /// Map keys include every byte. Keep the aligned tail deterministic instead
    /// of leaving four implicit stack bytes to split one flow into many keys.
    pub padding: [u8; 4],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct EcmCounters {
    pub bytes: u64,
    pub packets: u64,
    pub last_seen: u64,
}

/// Global evidence that the ECM probe separated hardware callbacks from
/// ordinary CPU slow-path updates before publishing client counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct EcmSourceStats {
    pub nss_bytes: u64,
    pub nss_packets: u64,
    pub nss_updates: u64,
    pub slow_path_bytes: u64,
    pub slow_path_packets: u64,
    pub slow_path_updates: u64,
}

/// Connection-deduplication key matching `struct lanspeed_conn_key`.
///
/// Every field is naturally contiguous under `repr(C)`: the six-byte MAC and
/// two one-byte tags place the network-order ports at offsets 8 and 10, then
/// the 16-byte destination address begins at offset 12. The resulting ABI is
/// 28 bytes with two-byte alignment and contains no implicit padding bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct LanspeedConnKey {
    pub mac: [u8; 6],
    pub proto: u8,
    pub family: u8,
    pub sport_be: u16,
    pub dport_be: u16,
    pub dst_ip: [u8; 16],
}

impl LanspeedConnKey {
    pub const fn new(
        mac: [u8; 6],
        proto: u8,
        family: u8,
        source_port: u16,
        destination_port: u16,
        dst_ip: [u8; 16],
    ) -> Self {
        Self {
            mac,
            proto,
            family,
            sport_be: source_port.to_be(),
            dport_be: destination_port.to_be(),
            dst_ip,
        }
    }

    pub const fn source_port(self) -> u16 {
        u16::from_be(self.sport_be)
    }

    pub const fn destination_port(self) -> u16 {
        u16::from_be(self.dport_be)
    }
}

const _: [(); 16] = [(); core::mem::size_of::<LanspeedKey>()];
const _: [(); 4] = [(); core::mem::align_of::<LanspeedKey>()];
const _: [(); 32] = [(); core::mem::size_of::<LanspeedCounters>()];
const _: [(); 8] = [(); core::mem::align_of::<LanspeedCounters>()];
const _: [(); 16] = [(); core::mem::size_of::<EcmLayout>()];
const _: [(); 4] = [(); core::mem::align_of::<EcmLayout>()];
const _: [(); 24] = [(); core::mem::size_of::<EcmKey>()];
const _: [(); 8] = [(); core::mem::align_of::<EcmKey>()];
const _: [(); 14] = [(); core::mem::offset_of!(EcmKey, mac)];
const _: [(); 20] = [(); core::mem::offset_of!(EcmKey, padding)];
const _: [(); 24] = [(); core::mem::size_of::<EcmCounters>()];
const _: [(); 8] = [(); core::mem::align_of::<EcmCounters>()];
const _: [(); 48] = [(); core::mem::size_of::<EcmSourceStats>()];
const _: [(); 8] = [(); core::mem::align_of::<EcmSourceStats>()];
const _: [(); 28] = [(); core::mem::size_of::<LanspeedConnKey>()];
const _: [(); 2] = [(); core::mem::align_of::<LanspeedConnKey>()];
