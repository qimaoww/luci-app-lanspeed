use core::ptr::{addr_of, addr_of_mut};

use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf,
    },
    macros::{kprobe, kretprobe, map},
    maps::{Array, LruHashMap, PerCpuHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use lanspeed_common::{
    packet::is_valid_client_mac, EcmCounters, EcmCountersUpdatedEvent, EcmEventStats, EcmKey,
    EcmLayout, EcmNssContext, EcmSourceStats, FastCounterValue, DIR_RX, DIR_TX,
    ECM_EVENT_RINGBUF_BYTES, ECM_FAST_COUNTERS_MAP_CAPACITY, ECM_SOURCE_NETDEV_V4,
    ECM_SOURCE_NETDEV_V6, ECM_SOURCE_SYNC_MANY_V4, ECM_SOURCE_SYNC_MANY_V6,
    FAST_COUNTER_ABI_VERSION, MAX_CLIENTS, MAX_ECM_NSS_CONTEXTS,
};

use crate::atomics::add_u64;

#[map(name = "lanspeed_ecm_clients")]
pub static LANSPEED_ECM_CLIENTS: LruHashMap<EcmKey, EcmCounters> =
    LruHashMap::with_max_entries(MAX_CLIENTS * 4, 0);

/// Per-CPU FastN cumulative counters. This map is independent from the
/// Evidence ledger above: the rate worker performs two lookups and accepts
/// only identical even sequences before building a same-window N/S delta.
#[map(name = "lanspeed_ecm_fast_counters")]
static LANSPEED_ECM_FAST_COUNTERS: PerCpuHashMap<EcmKey, FastCounterValue> =
    PerCpuHashMap::with_max_entries(ECM_FAST_COUNTERS_MAP_CAPACITY, 0);

#[map(name = "lanspeed_ecm_layout")]
pub static LANSPEED_ECM_LAYOUT: Array<EcmLayout> = Array::with_max_entries(1, 0);

#[map(name = "lanspeed_ecm_source_stats")]
pub static LANSPEED_ECM_SOURCE_STATS: Array<EcmSourceStats> = Array::with_max_entries(1, 0);

#[map(name = "lanspeed_ecm_nss_context")]
pub static LANSPEED_ECM_NSS_CONTEXT: LruHashMap<u64, EcmNssContext> =
    LruHashMap::with_max_entries(MAX_ECM_NSS_CONTEXTS, 0);

#[map(name = "lanspeed_ecm_event_ringbuf")]
pub static LANSPEED_ECM_EVENT_RINGBUF: RingBuf =
    RingBuf::with_byte_size(ECM_EVENT_RINGBUF_BYTES, 0);

#[map(name = "lanspeed_ecm_event_stats")]
pub static LANSPEED_ECM_EVENT_STATS: Array<EcmEventStats> = Array::with_max_entries(1, 0);

#[kprobe]
pub fn lanspeed_ecm_nss_enter_sync_many_v4(_ctx: ProbeContext) -> u32 {
    update_nss_context(true, ECM_SOURCE_SYNC_MANY_V4);
    0
}

#[kretprobe]
pub fn lanspeed_ecm_nss_exit_sync_many_v4(_ctx: RetProbeContext) -> u32 {
    update_nss_context(false, ECM_SOURCE_SYNC_MANY_V4);
    0
}

#[kprobe]
pub fn lanspeed_ecm_nss_enter_sync_many_v6(_ctx: ProbeContext) -> u32 {
    update_nss_context(true, ECM_SOURCE_SYNC_MANY_V6);
    0
}

#[kretprobe]
pub fn lanspeed_ecm_nss_exit_sync_many_v6(_ctx: RetProbeContext) -> u32 {
    update_nss_context(false, ECM_SOURCE_SYNC_MANY_V6);
    0
}

#[kprobe]
pub fn lanspeed_ecm_nss_enter_netdev_v4(_ctx: ProbeContext) -> u32 {
    update_nss_context(true, ECM_SOURCE_NETDEV_V4);
    0
}

#[kretprobe]
pub fn lanspeed_ecm_nss_exit_netdev_v4(_ctx: RetProbeContext) -> u32 {
    update_nss_context(false, ECM_SOURCE_NETDEV_V4);
    0
}

#[kprobe]
pub fn lanspeed_ecm_nss_enter_netdev_v6(_ctx: ProbeContext) -> u32 {
    update_nss_context(true, ECM_SOURCE_NETDEV_V6);
    0
}

#[kretprobe]
pub fn lanspeed_ecm_nss_exit_netdev_v6(_ctx: RetProbeContext) -> u32 {
    update_nss_context(false, ECM_SOURCE_NETDEV_V6);
    0
}

#[kprobe(function = "ecm_db_connection_data_totals_update")]
pub fn lanspeed_ecm_update(ctx: ProbeContext) -> u32 {
    try_ecm_update(&ctx);
    0
}

fn try_ecm_update(ctx: &ProbeContext) {
    let Some(connection) = ctx.arg::<u64>(0) else {
        return;
    };
    let Some(is_from) = ctx.arg::<u64>(1) else {
        return;
    };
    let Some(bytes) = ctx.arg::<u64>(2) else {
        return;
    };
    let Some(packets) = ctx.arg::<u64>(3) else {
        return;
    };
    if connection == 0 || (bytes == 0 && packets == 0) {
        return;
    }
    let nss = nss_context_active();
    record_source(nss, bytes, packets);
    if !nss {
        return;
    }
    let Some(layout) = LANSPEED_ECM_LAYOUT.get(0) else {
        return;
    };
    if layout.ready != 1 || layout.pointer_size != 8 {
        return;
    }

    let connection_ptr = connection as *const u8;
    let generation_ptr =
        unsafe { connection_ptr.add(layout.connection_generation_offset as usize) };
    let Ok(generation) = (unsafe { bpf_probe_read_kernel(generation_ptr.cast::<u32>()) }) else {
        return;
    };
    let from_mac = read_node_mac(connection_ptr, layout, layout.from_index);
    let to_mac = read_node_mac(connection_ptr, layout, layout.to_index);
    let (sender, receiver) = if is_from != 0 {
        (from_mac, to_mac)
    } else {
        (to_mac, from_mac)
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let mut accounted = false;
    if let Some(mac) = sender {
        accounted |= account(connection, generation, mac, DIR_TX, bytes, packets, now);
    }
    if let Some(mac) = receiver {
        accounted |= account(connection, generation, mac, DIR_RX, bytes, packets, now);
    }
    if accounted {
        mark_nss_context_dirty();
    }
}

#[inline(always)]
fn update_nss_context(enter: bool, source_id: u8) {
    // Entry and return probes can run on different CPUs after task migration.
    // Track nesting by pid_tgid so an old CPU cannot retain a false NSS context
    // and classify unrelated ECM slow-path updates as hardware increments.
    let task = bpf_get_current_pid_tgid();
    let current = LANSPEED_ECM_NSS_CONTEXT
        .get_ptr(&task)
        .map_or(EcmNssContext::default(), |context| unsafe {
            context.read_volatile()
        });
    if enter {
        let next = EcmNssContext {
            depth: current.depth.saturating_add(1),
            dirty: if current.depth == 0 { 0 } else { current.dirty },
            source_id: if current.depth == 0 {
                source_id
            } else {
                current.source_id
            },
            reserved: 0,
        };
        let _ = LANSPEED_ECM_NSS_CONTEXT.insert(&task, &next, 0);
    } else if current.depth > 1 {
        let next = EcmNssContext {
            depth: current.depth - 1,
            ..current
        };
        let _ = LANSPEED_ECM_NSS_CONTEXT.insert(&task, &next, 0);
    } else if current.depth == 1 {
        if current.dirty == 0 {
            let _ = LANSPEED_ECM_NSS_CONTEXT.remove(&task);
        } else {
            emit_counters_updated_event(current);
            let next = EcmNssContext {
                depth: 0,
                ..current
            };
            let _ = LANSPEED_ECM_NSS_CONTEXT.insert(&task, &next, 0);
        }
    }
}

#[inline(always)]
fn emit_counters_updated_event(context: EcmNssContext) {
    let Some(mut entry) = LANSPEED_ECM_EVENT_RINGBUF.reserve(0) else {
        if let Some(stats) = LANSPEED_ECM_EVENT_STATS.get_ptr_mut(0) {
            unsafe {
                add_u64(addr_of_mut!((*stats).ringbuf_reserve_fail), 1);
            }
        }
        return;
    };
    let sequence = LANSPEED_ECM_SOURCE_STATS
        .get_ptr(0)
        .map_or(0, |stats| unsafe {
            addr_of!((*stats).nss_updates).read_volatile()
        });
    entry.write(EcmCountersUpdatedEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        sequence,
        source: context.source_id,
        round_end: 0,
        reserved: [0; 6],
    });
    entry.submit(0);
    if let Some(stats) = LANSPEED_ECM_EVENT_STATS.get_ptr_mut(0) {
        unsafe {
            add_u64(addr_of_mut!((*stats).event_emit), 1);
        }
    }
}

#[inline(always)]
fn nss_context_active() -> bool {
    let task = bpf_get_current_pid_tgid();
    LANSPEED_ECM_NSS_CONTEXT
        .get_ptr(&task)
        .is_some_and(|context| unsafe { context.read_volatile().depth != 0 })
}

#[inline(always)]
fn mark_nss_context_dirty() {
    let task = bpf_get_current_pid_tgid();
    let Some(context) = LANSPEED_ECM_NSS_CONTEXT.get_ptr_mut(&task) else {
        return;
    };
    unsafe {
        (*context).dirty = 1;
    }
}

#[inline(always)]
fn record_source(nss: bool, bytes: u64, packets: u64) {
    let Some(value) = LANSPEED_ECM_SOURCE_STATS.get_ptr_mut(0) else {
        return;
    };
    unsafe {
        if nss {
            add_u64(addr_of_mut!((*value).nss_bytes), bytes);
            add_u64(addr_of_mut!((*value).nss_packets), packets);
            add_u64(addr_of_mut!((*value).nss_updates), 1);
        } else {
            add_u64(addr_of_mut!((*value).slow_path_bytes), bytes);
            add_u64(addr_of_mut!((*value).slow_path_packets), packets);
            add_u64(addr_of_mut!((*value).slow_path_updates), 1);
        }
    }
}

fn read_node_mac(connection: *const u8, layout: &EcmLayout, index: u8) -> Option<[u8; 6]> {
    if index >= 4 {
        return None;
    }
    let slot_offset = (layout.connection_node_offset as usize)
        .checked_add(index as usize * layout.pointer_size as usize)?;
    let slot = unsafe { connection.add(slot_offset).cast::<u64>() };
    let node = unsafe { bpf_probe_read_kernel(slot) }.ok()?;
    if node == 0 {
        return None;
    }
    let mut mac = [0u8; 6];
    let address = unsafe { (node as *const u8).add(layout.node_address_offset as usize) };
    unsafe { bpf_probe_read_kernel_buf(address, &mut mac) }.ok()?;
    is_valid_client_mac(mac).then_some(mac)
}

fn account(
    _connection: u64,
    _generation: u32,
    mac: [u8; 6],
    direction: u8,
    bytes: u64,
    packets: u64,
    now: u64,
) -> bool {
    // Keep the existing EcmKey ABI so a new object can be loaded by old and
    // new userspace, but aggregate the hot map by MAC + client direction.
    // Per-connection keys multiplied occupancy by the flow count and made LRU
    // eviction look like traffic loss on busy routers.  The callback context
    // above already proves these bytes are NSS hardware increments, so neither
    // the connection pointer nor its generation is needed for accounting.
    let key = EcmKey {
        connection: 0,
        generation: 0,
        direction,
        reserved: 0,
        mac,
        padding: [0; 4],
    };
    let fast_accounted = unsafe { update_fast_counter(&key, bytes, packets, now) };
    let ledger_accounted = match LANSPEED_ECM_CLIENTS.get_ptr_mut(&key) {
        Some(value) => unsafe {
            add_u64(addr_of_mut!((*value).bytes), bytes);
            add_u64(addr_of_mut!((*value).packets), packets);
            addr_of_mut!((*value).last_seen).write_volatile(now);
            true
        },
        None => {
            let initial = EcmCounters {
                bytes,
                packets,
                last_seen: now,
            };
            if LANSPEED_ECM_CLIENTS
                .insert(&key, &initial, BPF_NOEXIST as u64)
                .is_ok()
            {
                true
            } else if let Some(value) = LANSPEED_ECM_CLIENTS.get_ptr_mut(&key) {
                unsafe {
                    add_u64(addr_of_mut!((*value).bytes), bytes);
                    add_u64(addr_of_mut!((*value).packets), packets);
                    addr_of_mut!((*value).last_seen).write_volatile(now);
                }
                true
            } else {
                false
            }
        }
    };
    fast_accounted || ledger_accounted
}

#[inline(always)]
unsafe fn update_fast_counter(key: &EcmKey, bytes: u64, packets: u64, now: u64) -> bool {
    let Some(counter) = LANSPEED_ECM_FAST_COUNTERS.get_ptr_mut(key) else {
        let initial = FastCounterValue {
            abi_version: FAST_COUNTER_ABI_VERSION,
            reset_generation: 1,
            seq: 2,
            bytes,
            packets,
            last_seen_ns: now,
        };
        if LANSPEED_ECM_FAST_COUNTERS
            .insert(key, &initial, BPF_NOEXIST as u64)
            .is_ok()
        {
            return true;
        }
        let Some(counter) = LANSPEED_ECM_FAST_COUNTERS.get_ptr_mut(key) else {
            return false;
        };
        return unsafe { update_existing_fast_counter(counter, bytes, packets, now) };
    };
    unsafe { update_existing_fast_counter(counter, bytes, packets, now) }
}

#[inline(always)]
unsafe fn update_existing_fast_counter(
    counter: *mut FastCounterValue,
    bytes: u64,
    packets: u64,
    now: u64,
) -> bool {
    let abi_version = unsafe { addr_of_mut!((*counter).abi_version).read_volatile() };
    let reset_generation = unsafe { addr_of_mut!((*counter).reset_generation).read_volatile() };
    let sequence_value = unsafe { addr_of_mut!((*counter).seq).read_volatile() };
    if abi_version != FAST_COUNTER_ABI_VERSION || reset_generation == 0 || sequence_value & 1 != 0 {
        unsafe {
            addr_of_mut!((*counter).seq).write_volatile(1);
            addr_of_mut!((*counter).abi_version).write_volatile(FAST_COUNTER_ABI_VERSION);
            addr_of_mut!((*counter).reset_generation).write_volatile(1);
            addr_of_mut!((*counter).bytes).write_volatile(bytes);
            addr_of_mut!((*counter).packets).write_volatile(packets);
            addr_of_mut!((*counter).last_seen_ns).write_volatile(now);
            addr_of_mut!((*counter).seq).write_volatile(2);
        }
        return true;
    }

    // Per-CPU ownership makes the odd/even sequence the publication barrier
    // for this slot. Userspace still performs two complete map lookups so a
    // copied value is never accepted merely because its first seq was even.
    let sequence = unsafe { addr_of_mut!((*counter).seq) };
    unsafe {
        add_u64(sequence, 1);
        add_u64(addr_of_mut!((*counter).bytes), bytes);
        add_u64(addr_of_mut!((*counter).packets), packets);
        addr_of_mut!((*counter).last_seen_ns).write_volatile(now);
        add_u64(sequence, 1);
    }
    true
}
