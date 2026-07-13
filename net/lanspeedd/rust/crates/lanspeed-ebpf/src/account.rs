use core::{mem::MaybeUninit, ptr::addr_of_mut, slice};

use aya_ebpf::helpers::generated::bpf_skb_load_bytes;
use aya_ebpf::{
    bindings::BPF_NOEXIST, helpers::bpf_ktime_get_ns, macros::map, maps::LruHashMap,
    programs::TcContext,
};
use lanspeed_common::{
    accounting::tc_frame_accounting,
    packet::{gro_repeated_header_len, is_valid_client_mac, vlan_zone},
    LanspeedConnKey, LanspeedCounters, LanspeedKey, DIR_TX, MAX_CLIENTS, MAX_CONN_TUPLES,
};

#[cfg(feature = "conntrack-kfunc")]
use crate::conntrack::try_count_connection;
#[cfg(feature = "conntrack-kfunc")]
use lanspeed_common::packet::parse_packet_prefix;

const ETHERNET_HEADER_LEN: usize = 14;
const PACKET_PREFIX_LEN: usize = 142;

#[map(name = "lanspeed_clients")]
pub static LANSPEED_CLIENTS: LruHashMap<LanspeedKey, LanspeedCounters> =
    LruHashMap::with_max_entries(MAX_CLIENTS, 0);

#[map(name = "lanspeed_seen_conns")]
pub static LANSPEED_SEEN_CONNS: LruHashMap<LanspeedConnKey, u8> =
    LruHashMap::with_max_entries(MAX_CONN_TUPLES, 0);

pub fn account_frame(ctx: TcContext, direction: u8, action: i32) -> i32 {
    let frame_len = ctx.len();
    if frame_len < ETHERNET_HEADER_LEN as u32 {
        return action;
    }
    let mut prefix = MaybeUninit::<[u8; PACKET_PREFIX_LEN]>::uninit();
    let prefix_ptr = prefix.as_mut_ptr().cast::<u8>();
    if !load_packet_prefix(&ctx, prefix_ptr, ETHERNET_HEADER_LEN as u32) {
        return action;
    }
    let ethernet = unsafe { loaded_packet_prefix(&prefix, ETHERNET_HEADER_LEN as u32) };

    let mac = if direction == DIR_TX {
        [
            ethernet[6],
            ethernet[7],
            ethernet[8],
            ethernet[9],
            ethernet[10],
            ethernet[11],
        ]
    } else {
        [
            ethernet[0],
            ethernet[1],
            ethernet[2],
            ethernet[3],
            ethernet[4],
            ethernet[5],
        ]
    };
    if !is_valid_client_mac(mac) {
        return action;
    }

    let skb = ctx.skb.skb;
    let wire_len = unsafe { (*skb).wire_len };
    let gso_segs = unsafe { (*skb).gso_segs };
    let prefix_len = frame_len.min(PACKET_PREFIX_LEN as u32);
    let gro_prefix_loaded =
        direction == DIR_TX && gso_segs > 1 && load_packet_prefix(&ctx, prefix_ptr, prefix_len);
    let ingress_header_len = if gro_prefix_loaded {
        gro_repeated_header_len(unsafe { loaded_packet_prefix(&prefix, prefix_len) })
    } else {
        None
    };
    let accounting =
        tc_frame_accounting(direction, frame_len, wire_len, gso_segs, ingress_header_len);
    let key = LanspeedKey {
        ifindex: unsafe { (*skb).ifindex },
        vlan_or_zone: vlan_zone(unsafe { (*skb).vlan_tci } as u16),
        direction,
        reserved: 0,
        mac,
        padding: [0; 2],
    };
    let now = unsafe { bpf_ktime_get_ns() };

    let counters = match LANSPEED_CLIENTS.get_ptr_mut(&key) {
        Some(counters) => {
            unsafe { add_packet(counters, accounting.bytes, accounting.packets, now) };
            counters
        }
        None => {
            let initial = LanspeedCounters {
                bytes: accounting.bytes,
                packets: accounting.packets,
                last_seen: now,
                tcp_conns: 0,
                udp_conns: 0,
            };
            let inserted = LANSPEED_CLIENTS
                .insert(&key, &initial, BPF_NOEXIST as u64)
                .is_ok();
            let Some(counters) = LANSPEED_CLIENTS.get_ptr_mut(&key) else {
                return action;
            };
            if !inserted {
                unsafe { add_packet(counters, accounting.bytes, accounting.packets, now) };
            }
            counters
        }
    };

    #[cfg(not(feature = "conntrack-kfunc"))]
    let _ = counters;

    #[cfg(feature = "conntrack-kfunc")]
    if direction == DIR_TX {
        let mut prefix_loaded = gro_prefix_loaded;
        if !prefix_loaded {
            prefix_loaded = load_packet_prefix(&ctx, prefix_ptr, prefix_len);
        }
        if prefix_loaded {
            let loaded_prefix = unsafe { loaded_packet_prefix(&prefix, prefix_len) };
            if let Ok(packet) = parse_packet_prefix(loaded_prefix, frame_len as usize) {
                try_count_connection(&ctx, counters, mac, packet);
            }
        }
    }

    action
}

#[inline(always)]
fn load_packet_prefix(ctx: &TcContext, prefix: *mut u8, prefix_len: u32) -> bool {
    unsafe { bpf_skb_load_bytes(ctx.skb.skb.cast(), 0, prefix.cast(), prefix_len) == 0 }
}

#[inline(always)]
unsafe fn loaded_packet_prefix(
    prefix: &MaybeUninit<[u8; PACKET_PREFIX_LEN]>,
    prefix_len: u32,
) -> &[u8] {
    // SAFETY: callers only reach this helper after bpf_skb_load_bytes has
    // successfully initialized exactly the returned prefix range.
    unsafe { slice::from_raw_parts(prefix.as_ptr().cast::<u8>(), prefix_len as usize) }
}

unsafe fn add_packet(counters: *mut LanspeedCounters, bytes: u64, packets: u64, now: u64) {
    let bytes_counter = unsafe { addr_of_mut!((*counters).bytes) };
    let packets_counter = unsafe { addr_of_mut!((*counters).packets) };
    unsafe {
        core::intrinsics::atomic_xadd::<_, _, { core::intrinsics::AtomicOrdering::Relaxed }>(
            bytes_counter,
            bytes,
        );
        core::intrinsics::atomic_xadd::<_, _, { core::intrinsics::AtomicOrdering::Relaxed }>(
            packets_counter,
            packets,
        );
        addr_of_mut!((*counters).last_seen).write_volatile(now);
    }
}
