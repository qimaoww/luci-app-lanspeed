#![no_std]

pub mod accounting;
pub mod packet;

pub const CLIENTS_MAP_NAME: &str = "lanspeed_clients";
pub const SEEN_CONNS_MAP_NAME: &str = "lanspeed_seen_conns";
pub const ECM_CLIENTS_MAP_NAME: &str = "lanspeed_ecm_clients";
pub const ECM_LAYOUT_MAP_NAME: &str = "lanspeed_ecm_layout";
pub const ECM_NSS_CONTEXT_MAP_NAME: &str = "lanspeed_ecm_nss_context";
pub const ECM_SOURCE_STATS_MAP_NAME: &str = "lanspeed_ecm_source_stats";
pub const ECM_EVENT_RINGBUF_MAP_NAME: &str = "lanspeed_ecm_event_ringbuf";
pub const ECM_EVENT_STATS_MAP_NAME: &str = "lanspeed_ecm_event_stats";
pub const ECM_FAST_COUNTERS_MAP_NAME: &str = "lanspeed_ecm_fast_counters";
pub const FAST_COUNTERS_MAP_NAME: &str = "lanspeed_fast_counters";

pub const INGRESS_PROGRAM_NAME: &str = "lanspeed_ingress";
pub const EGRESS_PROGRAM_NAME: &str = "lanspeed_egress";
pub const INGRESS_EARLY_PROGRAM_NAME: &str = "lanspeed_ingress_early";
pub const EGRESS_EARLY_PROGRAM_NAME: &str = "lanspeed_egress_early";
pub const ECM_UPDATE_PROGRAM_NAME: &str = "lanspeed_ecm_update";
pub const ECM_NSS_ENTER_SYNC_MANY_V4_PROGRAM_NAME: &str = "lanspeed_ecm_nss_enter_sync_many_v4";
pub const ECM_NSS_EXIT_SYNC_MANY_V4_PROGRAM_NAME: &str = "lanspeed_ecm_nss_exit_sync_many_v4";
pub const ECM_NSS_ENTER_SYNC_MANY_V6_PROGRAM_NAME: &str = "lanspeed_ecm_nss_enter_sync_many_v6";
pub const ECM_NSS_EXIT_SYNC_MANY_V6_PROGRAM_NAME: &str = "lanspeed_ecm_nss_exit_sync_many_v6";
pub const ECM_NSS_ENTER_NETDEV_V4_PROGRAM_NAME: &str = "lanspeed_ecm_nss_enter_netdev_v4";
pub const ECM_NSS_EXIT_NETDEV_V4_PROGRAM_NAME: &str = "lanspeed_ecm_nss_exit_netdev_v4";
pub const ECM_NSS_ENTER_NETDEV_V6_PROGRAM_NAME: &str = "lanspeed_ecm_nss_enter_netdev_v6";
pub const ECM_NSS_EXIT_NETDEV_V6_PROGRAM_NAME: &str = "lanspeed_ecm_nss_exit_netdev_v6";

pub const ECM_SOURCE_SYNC_MANY_V4: u8 = 1;
pub const ECM_SOURCE_SYNC_MANY_V6: u8 = 2;
pub const ECM_SOURCE_NETDEV_V4: u8 = 3;
pub const ECM_SOURCE_NETDEV_V6: u8 = 4;

pub const MAX_CLIENTS: u32 = 2048;
pub const MAX_CONN_TUPLES: u32 = 8192;
pub const MAX_ECM_NSS_CONTEXTS: u32 = 4096;
pub const ECM_EVENT_RINGBUF_BYTES: u32 = 64 * 1024;
pub const FAST_COUNTER_ABI_VERSION: u32 = 1;
pub const FAST_COUNTERS_MAP_CAPACITY: u32 = MAX_CLIENTS;
pub const ECM_FAST_COUNTERS_MAP_CAPACITY: u32 = MAX_CLIENTS * 2;

/// Versioned read-only NSS control ABI. The C module mirrors these values in
/// its public control header; keeping the Rust side in the common crate makes
/// every parser and contract test consume one userspace definition.
pub mod nss_genl {
    pub const FAMILY_NAME: &str = "LANSPEED_NSS";
    pub const VERSION: u8 = 1;

    pub const CMD_GET_CAPS: u8 = 1;
    pub const CMD_GET_STATE: u8 = 2;
    pub const CMD_GET_STATS: u8 = 3;
    pub const CMD_GET_HEALTH: u8 = 4;
    pub const CMD_IGS_STAGE: u8 = 5;
    pub const CMD_IGS_PUBLISH: u8 = 6;
    pub const CMD_IGS_UNPUBLISH: u8 = 7;
    pub const CMD_IGS_DELETE: u8 = 8;
    pub const CMD_PEER_REPLACE: u8 = 9;
    pub const CMD_TAG_REPLACE: u8 = 10;
    pub const CMD_TRUSTED_INGRESS_REPLACE: u8 = 11;

    pub const A_ABI_VERSION: u16 = 1;
    pub const A_FEATURE_BITS: u16 = 2;
    pub const A_MAX_IGS: u16 = 3;
    pub const A_MAX_PEERS: u16 = 4;
    pub const A_MAX_CLIENT_TAGS: u16 = 5;
    pub const A_SUPPORTS_WIFI_PEER: u16 = 6;
    pub const A_SUPPORTS_IGS_STATS: u16 = 7;
    pub const A_SUPPORTS_PEER_QUERY: u16 = 8;
    pub const A_IGS_STAGED: u16 = 9;
    pub const A_IGS_PUBLISHED: u16 = 10;
    pub const A_IGS_DEGRADED: u16 = 11;
    pub const A_CONTROL_GENERATION: u16 = 12;
    pub const A_HARDWARE_GENERATION: u16 = 13;
    pub const A_PEER_GENERATION: u16 = 14;
    pub const A_IGS_SYNC_COUNT: u16 = 15;
    pub const A_IGS_LAST_SYNC_NS: u16 = 16;
    pub const A_IGS_BYTES: u16 = 17;
    pub const A_IGS_PACKETS: u16 = 18;
    pub const A_IGS_DROPS: u16 = 19;
    pub const A_ACK_LATENCY_LAST_NS: u16 = 20;
    pub const A_ACK_LATENCY_MAX_NS: u16 = 21;
    pub const A_ACK_RECEIVED: u16 = 22;
    pub const A_ACK_TIMEOUT: u16 = 23;
    pub const A_ACK_LATE: u16 = 24;
    pub const A_HEALTHY: u16 = 25;
    pub const A_PEER_REASSERT_COUNT: u16 = 26;
    pub const A_IFB_NAME: u16 = 27;
    pub const A_EDGE_NAME: u16 = 28;
    pub const A_CONFIG: u16 = 29;
    pub const A_IGS_CADENCE_SAMPLES: u16 = 30;
    pub const A_IGS_CADENCE_LAST_NS: u16 = 31;
    pub const A_IGS_CADENCE_MIN_NS: u16 = 32;
    pub const A_IGS_CADENCE_MAX_NS: u16 = 33;
    pub const A_IGS_ACTIVE_NODES: u16 = 34;

    pub const FEATURE_IGS: u32 = 1 << 0;
    pub const FEATURE_WIFI_PEER: u32 = 1 << 1;
    pub const FEATURE_IGS_STATS: u32 = 1 << 2;
    pub const FEATURE_PEER_QUERY: u32 = 1 << 3;
    pub const FEATURE_RCU_TAGS: u32 = 1 << 4;
    pub const FEATURE_TRUSTED_INGRESS: u32 = 1 << 5;
    pub const FEATURE_IGS_CADENCE: u32 = 1 << 6;
}

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

/// Per-task state for the ECM NSS callback boundary.
///
/// `depth` tracks nested callbacks. `dirty` is set only after the totals
/// update probe successfully accounts at least one valid client counter while
/// inside the callback. `source_id` is reserved for the source-specific
/// callback programs; the initial ABI uses zero until those programs are
/// attached independently.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(4))]
pub struct EcmNssContext {
    pub depth: u32,
    pub dirty: u8,
    pub source_id: u8,
    pub reserved: u16,
}

/// A callback-boundary hint. It never claims that a complete NSS round ended;
/// `round_end` therefore remains zero until a stable vendor completion signal
/// exists.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct EcmCountersUpdatedEvent {
    pub timestamp_ns: u64,
    pub sequence: u64,
    pub source: u8,
    pub round_end: u8,
    pub reserved: [u8; 6],
}

/// Kernel-side counters for the best-effort event hint channel.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct EcmEventStats {
    pub event_emit: u64,
    pub ringbuf_reserve_fail: u64,
}

/// Stable-read ABI for the FastN/FastS counter plane.
///
/// Writers publish an odd `seq` before changing the three counter fields and
/// an even `seq` after the write. Readers must observe the same even sequence
/// in two bounded lookups before accepting the value. `reset_generation`
/// changes on BPF reload or counter reset and is never inferred from bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C, align(8))]
pub struct FastCounterValue {
    pub abi_version: u32,
    pub reset_generation: u32,
    pub seq: u64,
    pub bytes: u64,
    pub packets: u64,
    pub last_seen_ns: u64,
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
const _: [(); 8] = [(); core::mem::size_of::<EcmNssContext>()];
const _: [(); 4] = [(); core::mem::align_of::<EcmNssContext>()];
const _: [(); 24] = [(); core::mem::size_of::<EcmCountersUpdatedEvent>()];
const _: [(); 8] = [(); core::mem::align_of::<EcmCountersUpdatedEvent>()];
const _: [(); 16] = [(); core::mem::size_of::<EcmEventStats>()];
const _: [(); 8] = [(); core::mem::align_of::<EcmEventStats>()];
const _: [(); 40] = [(); core::mem::size_of::<FastCounterValue>()];
const _: [(); 8] = [(); core::mem::align_of::<FastCounterValue>()];
const _: [(); 0] = [(); core::mem::offset_of!(FastCounterValue, abi_version)];
const _: [(); 4] = [(); core::mem::offset_of!(FastCounterValue, reset_generation)];
const _: [(); 8] = [(); core::mem::offset_of!(FastCounterValue, seq)];
const _: [(); 16] = [(); core::mem::offset_of!(FastCounterValue, bytes)];
const _: [(); 24] = [(); core::mem::offset_of!(FastCounterValue, packets)];
const _: [(); 32] = [(); core::mem::offset_of!(FastCounterValue, last_seen_ns)];
const _: [(); 28] = [(); core::mem::size_of::<LanspeedConnKey>()];
const _: [(); 2] = [(); core::mem::align_of::<LanspeedConnKey>()];
