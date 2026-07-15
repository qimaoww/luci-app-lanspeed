use core::{mem::MaybeUninit, ptr::addr_of_mut};

use aya_ebpf::{
    bindings::{
        bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 as BpfIpv4Tuple,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2 as BpfIpv6Tuple, BPF_NOEXIST,
    },
    macros::map,
    maps::PerCpuArray,
    programs::TcContext,
};
use lanspeed_common::{
    packet::{parse_packet_prefix, AddressFamily, PacketIdentity, TransportProtocol},
    LanspeedConnKey, LanspeedCounters,
};

use crate::account::LANSPEED_SEEN_CONNS;

#[repr(C)]
struct BpfCtOpts {
    netns_id: i32,
    error: i32,
    l4proto: u8,
    dir: u8,
    reserved: [u8; 2],
}

#[repr(C)]
struct NfConn {
    _private: [u8; 0],
}

#[repr(C)]
struct ConntrackScratch {
    // PacketIdentity contains enums, so keep the zero-initialized map slot in
    // MaybeUninit until the bounded parser has produced a complete value.
    packet: MaybeUninit<PacketIdentity>,
    conn_key: LanspeedConnKey,
    tuple: bpf_sock_tuple,
    opts: BpfCtOpts,
}

#[map(name = "lanspeed_conntrack_scratch")]
static LANSPEED_CONNTRACK_SCRATCH: PerCpuArray<ConntrackScratch> =
    PerCpuArray::with_max_entries(1, 0);

#[allow(dead_code)]
unsafe extern "C" {
    fn bpf_skb_ct_lookup(
        skb: *mut aya_ebpf::bindings::__sk_buff,
        tuple: *mut bpf_sock_tuple,
        tuple_size: u32,
        opts: *mut BpfCtOpts,
        opts_size: u32,
    ) -> *mut NfConn;
    fn bpf_ct_release(conn: *mut NfConn);
}

pub fn try_count_connection(
    ctx: &TcContext,
    counters: *mut LanspeedCounters,
    mac: [u8; 6],
    prefix: &[u8],
    frame_len: usize,
) {
    let Some(scratch) = LANSPEED_CONNTRACK_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    let scratch = unsafe { &mut *scratch };
    let Ok(packet) = parse_packet_prefix(prefix, frame_len) else {
        return;
    };
    scratch.packet.write(packet);
    let packet = unsafe { scratch.packet.assume_init_ref() };
    scratch.conn_key = LanspeedConnKey::new(
        mac,
        packet.protocol as u8,
        packet.family as u8,
        packet.src_port,
        packet.dst_port,
        packet.dst_addr,
    );
    if LANSPEED_SEEN_CONNS.get_ptr(&scratch.conn_key).is_some() {
        return;
    }

    let tuple_size = match packet.family {
        AddressFamily::Ipv4 => {
            scratch.tuple.__bindgen_anon_1.ipv4 = BpfIpv4Tuple {
                saddr: u32::from_ne_bytes([
                    packet.src_addr[0],
                    packet.src_addr[1],
                    packet.src_addr[2],
                    packet.src_addr[3],
                ]),
                daddr: u32::from_ne_bytes([
                    packet.dst_addr[0],
                    packet.dst_addr[1],
                    packet.dst_addr[2],
                    packet.dst_addr[3],
                ]),
                sport: packet.src_port.to_be(),
                dport: packet.dst_port.to_be(),
            };
            size_of::<BpfIpv4Tuple>() as u32
        }
        AddressFamily::Ipv6 => {
            scratch.tuple.__bindgen_anon_1.ipv6 = BpfIpv6Tuple {
                saddr: ipv6_words(packet.src_addr),
                daddr: ipv6_words(packet.dst_addr),
                sport: packet.src_port.to_be(),
                dport: packet.dst_port.to_be(),
            };
            size_of::<BpfIpv6Tuple>() as u32
        }
    };
    scratch.opts = BpfCtOpts {
        netns_id: -1,
        error: 0,
        l4proto: packet.protocol as u8,
        dir: 0,
        reserved: [0; 2],
    };

    let conn = unsafe {
        call_bpf_skb_ct_lookup(
            ctx.skb.skb,
            &mut scratch.tuple,
            tuple_size,
            &mut scratch.opts,
            size_of::<BpfCtOpts>() as u32,
        )
    };
    if conn.is_null() {
        return;
    }
    unsafe { call_bpf_ct_release(conn) };

    let seen = 1u8;
    if LANSPEED_SEEN_CONNS
        .insert(&scratch.conn_key, &seen, BPF_NOEXIST as u64)
        .is_err()
    {
        return;
    }

    let counter = match packet.protocol {
        TransportProtocol::Tcp => unsafe { addr_of_mut!((*counters).tcp_conns) },
        TransportProtocol::Udp => unsafe { addr_of_mut!((*counters).udp_conns) },
    };
    unsafe {
        core::intrinsics::atomic_xadd::<_, _, { core::intrinsics::AtomicOrdering::Relaxed }>(
            counter, 1u32,
        );
    }
}

#[inline(always)]
unsafe fn call_bpf_skb_ct_lookup(
    skb: *mut aya_ebpf::bindings::__sk_buff,
    tuple: *mut bpf_sock_tuple,
    tuple_size: u32,
    opts: *mut BpfCtOpts,
    opts_size: u32,
) -> *mut NfConn {
    let result: *mut NfConn;
    unsafe {
        core::arch::asm!(
            "call bpf_skb_ct_lookup",
            inlateout("r1") skb => _,
            inlateout("r2") tuple => _,
            inlateout("r3") tuple_size => _,
            inlateout("r4") opts => _,
            inlateout("r5") opts_size => _,
            lateout("r0") result,
            options(nostack),
        );
    }
    result
}

#[inline(always)]
unsafe fn call_bpf_ct_release(conn: *mut NfConn) {
    unsafe {
        core::arch::asm!(
            "call bpf_ct_release",
            inlateout("r1") conn => _,
            lateout("r0") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
            options(nostack),
        );
    }
}

fn ipv6_words(address: [u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([address[0], address[1], address[2], address[3]]),
        u32::from_ne_bytes([address[4], address[5], address[6], address[7]]),
        u32::from_ne_bytes([address[8], address[9], address[10], address[11]]),
        u32::from_ne_bytes([address[12], address[13], address[14], address[15]]),
    ]
}
