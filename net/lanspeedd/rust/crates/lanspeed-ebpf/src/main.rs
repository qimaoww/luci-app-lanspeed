#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]
#![feature(asm_experimental_arch)]

mod account;
mod atomics;
#[cfg(feature = "conntrack-kfunc")]
mod conntrack;
mod panic;

use account::account_frame;
use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_UNSPEC},
    macros::classifier,
    programs::TcContext,
};
use lanspeed_common::{DIR_RX, DIR_TX};

#[link_section = "license"]
#[no_mangle]
// Rust sources remain Apache-2.0; this kernel ABI marker is GPL because the
// conntrack kfuncs are exported only to GPL-compatible BPF programs.
static LICENSE: [u8; 4] = *b"GPL\0";

#[classifier]
pub fn lanspeed_ingress(ctx: TcContext) -> i32 {
    account_frame(ctx, DIR_TX, TC_ACT_OK)
}

#[classifier]
pub fn lanspeed_egress(ctx: TcContext) -> i32 {
    account_frame(ctx, DIR_RX, TC_ACT_OK)
}

#[classifier]
pub fn lanspeed_ingress_early(ctx: TcContext) -> i32 {
    account_frame(ctx, DIR_TX, TC_ACT_UNSPEC)
}

#[classifier]
pub fn lanspeed_egress_early(ctx: TcContext) -> i32 {
    account_frame(ctx, DIR_RX, TC_ACT_UNSPEC)
}
