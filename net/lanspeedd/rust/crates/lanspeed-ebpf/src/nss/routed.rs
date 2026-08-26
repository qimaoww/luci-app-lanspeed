//! FIB-based scope guard for the NSS TC slow path.
//!
//! FastS is attached to the LAN bridge and therefore sees both forwarded
//! Internet traffic and frames generated or terminated by the router. A
//! reverse FIB lookup of the non-client endpoint separates those domains
//! without hard-coding the LAN prefix: local routes return NOT_FWDED, while a
//! route back through the observed LAN interface is same-side LAN traffic.

use core::mem::size_of;

use aya_ebpf::{
    bindings::{
        bpf_fib_lookup, BPF_FIB_LKUP_RET_NOT_FWDED, BPF_FIB_LKUP_RET_NO_NEIGH,
        BPF_FIB_LKUP_RET_SUCCESS, BPF_FIB_LOOKUP_SKIP_NEIGH,
    },
    helpers::generated::bpf_fib_lookup as fib_lookup,
    macros::map,
    maps::PerCpuArray,
    programs::TcContext,
};
use lanspeed_common::{packet::RouteAddresses, DIR_RX};

#[map(name = "lanspeed_fib_lookup")]
static LANSPEED_FIB_LOOKUP: PerCpuArray<bpf_fib_lookup> = PerCpuArray::with_max_entries(1, 0);

pub(super) fn is_lan_local_frame(
    ctx: &TcContext,
    addresses: RouteAddresses,
    direction: u8,
    lan_ifindex: u32,
) -> bool {
    let Some(params) = LANSPEED_FIB_LOOKUP.get_ptr_mut(0) else {
        return false;
    };
    let params = unsafe { &mut *params };
    params.l4_protocol = 0;
    params.sport = 0;
    params.dport = 0;
    params.__bindgen_anon_1.tot_len = 0;
    params.__bindgen_anon_2.tos = 0;
    params.__bindgen_anon_5.tbid = 0;
    params.ifindex = lan_ifindex;
    match addresses {
        RouteAddresses::Ipv4 { src, dst } => {
            params.family = 2;
            if direction == DIR_RX {
                params.__bindgen_anon_3.ipv4_src = u32::from_ne_bytes(dst);
                params.__bindgen_anon_4.ipv4_dst = u32::from_ne_bytes(src);
            } else {
                params.__bindgen_anon_3.ipv4_src = u32::from_ne_bytes(src);
                params.__bindgen_anon_4.ipv4_dst = u32::from_ne_bytes(dst);
            }
        }
        RouteAddresses::Ipv6 { src, dst } => {
            params.family = 10;
            if direction == DIR_RX {
                params.__bindgen_anon_3.ipv6_src = ipv6_words(dst);
                params.__bindgen_anon_4.ipv6_dst = ipv6_words(src);
            } else {
                params.__bindgen_anon_3.ipv6_src = ipv6_words(src);
                params.__bindgen_anon_4.ipv6_dst = ipv6_words(dst);
            }
        }
    }
    let result = unsafe {
        fib_lookup(
            ctx.skb.skb.cast(),
            params,
            size_of::<bpf_fib_lookup>() as i32,
            BPF_FIB_LOOKUP_SKIP_NEIGH,
        )
    } as u32;
    result == BPF_FIB_LKUP_RET_NOT_FWDED
        || matches!(result, BPF_FIB_LKUP_RET_SUCCESS | BPF_FIB_LKUP_RET_NO_NEIGH)
            && params.ifindex == lan_ifindex
}

#[inline(always)]
fn ipv6_words(address: [u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([address[0], address[1], address[2], address[3]]),
        u32::from_ne_bytes([address[4], address[5], address[6], address[7]]),
        u32::from_ne_bytes([address[8], address[9], address[10], address[11]]),
        u32::from_ne_bytes([address[12], address[13], address[14], address[15]]),
    ]
}
