#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use lanspeed_common::BYTE_COUNT_KEY;

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[map(name = "BYTE_COUNTS")]
static BYTE_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[classifier]
pub fn lanspeed_count(ctx: TcContext) -> i32 {
    count_bytes(ctx)
}

fn count_bytes(ctx: TcContext) -> i32 {
    let packet_bytes = ctx.len() as u64;

    unsafe {
        if let Some(counter) = BYTE_COUNTS.get_ptr_mut(&BYTE_COUNT_KEY) {
            *counter += packet_bytes;
        } else {
            let _ = BYTE_COUNTS.insert(&BYTE_COUNT_KEY, &packet_bytes, 0);
        }
    }

    TC_ACT_PIPE
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
