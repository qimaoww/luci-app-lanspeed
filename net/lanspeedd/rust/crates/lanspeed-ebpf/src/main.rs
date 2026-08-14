#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]
#![cfg_attr(feature = "conntrack-kfunc", feature(asm_experimental_arch))]

#[cfg(all(feature = "x86-tc", feature = "nss-tc"))]
compile_error!("x86-tc and nss-tc are mutually exclusive");

mod atomics;
#[cfg(any(feature = "nss-tc", feature = "nss-ecm"))]
mod nss;
mod panic;
#[cfg(feature = "x86-tc")]
mod x86;

#[cfg(feature = "nss-tc")]
use aya_ebpf::bindings::TC_ACT_OK;
#[cfg(feature = "tc")]
use aya_ebpf::{bindings::TC_ACT_UNSPEC, macros::classifier, programs::TcContext};
#[cfg(feature = "tc")]
use lanspeed_common::{DIR_RX, DIR_TX};
#[cfg(feature = "nss-tc")]
use nss::account_frame;
#[cfg(feature = "x86-tc")]
use x86::account_frame;

#[cfg(feature = "nss-ecm")]
pub use nss::{
    lanspeed_ecm_nss_enter_netdev_v4, lanspeed_ecm_nss_enter_netdev_v6,
    lanspeed_ecm_nss_enter_sync_many_v4, lanspeed_ecm_nss_enter_sync_many_v6,
    lanspeed_ecm_nss_exit_netdev_v4, lanspeed_ecm_nss_exit_netdev_v6,
    lanspeed_ecm_nss_exit_sync_many_v4, lanspeed_ecm_nss_exit_sync_many_v6, lanspeed_ecm_update,
};

#[link_section = "license"]
#[no_mangle]
// Rust sources remain Apache-2.0; this kernel ABI marker is GPL because the
// conntrack kfuncs are exported only to GPL-compatible BPF programs.
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(feature = "tc")]
#[classifier]
pub fn lanspeed_ingress(ctx: TcContext) -> i32 {
    #[cfg(feature = "x86-tc")]
    return account_frame(ctx, DIR_TX, TC_ACT_UNSPEC);
    #[cfg(not(feature = "x86-tc"))]
    account_frame(ctx, DIR_TX, TC_ACT_OK)
}

#[cfg(feature = "tc")]
#[classifier]
pub fn lanspeed_egress(ctx: TcContext) -> i32 {
    #[cfg(feature = "x86-tc")]
    return account_frame(ctx, DIR_RX, TC_ACT_UNSPEC);
    #[cfg(not(feature = "x86-tc"))]
    account_frame(ctx, DIR_RX, TC_ACT_OK)
}

#[cfg(feature = "tc")]
#[classifier]
pub fn lanspeed_ingress_early(ctx: TcContext) -> i32 {
    account_frame(ctx, DIR_TX, TC_ACT_UNSPEC)
}

#[cfg(feature = "tc")]
#[classifier]
pub fn lanspeed_egress_early(ctx: TcContext) -> i32 {
    account_frame(ctx, DIR_RX, TC_ACT_UNSPEC)
}
