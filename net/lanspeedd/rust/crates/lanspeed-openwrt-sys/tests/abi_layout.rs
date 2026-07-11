#![allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn
)]

#[path = "../src/raw.rs"]
mod raw;

use std::mem::{align_of, offset_of, size_of};

macro_rules! layout {
    ($type:ty, $size:expr, $align:expr, $($field:ident => $offset:expr),+ $(,)?) => {{
        assert_eq!(size_of::<$type>(), $size, "{} size", stringify!($type));
        assert_eq!(align_of::<$type>(), $align, "{} alignment", stringify!($type));
        $(assert_eq!(offset_of!($type, $field), $offset, "{}::{} offset", stringify!($type), stringify!($field));)+
    }};
}

#[test]
fn blob_and_uloop_layout_matches_immortalwrt_x86_64_musl() {
    layout!(raw::blob_buf, 32, 8, head => 0, grow => 8, buflen => 16, buf => 24);
    layout!(raw::uloop_fd, 16, 8, cb => 0, fd => 8, eof => 12, error => 13, registered => 14, flags => 15);
    layout!(raw::uloop_timeout, 48, 8, list => 0, pending => 16, cb => 24, time => 32);
}

#[test]
fn ubus_layout_matches_immortalwrt_x86_64_musl() {
    layout!(raw::ubus_method, 48, 8, name => 0, handler => 8, mask => 16, tags => 24, policy => 32, n_policy => 40);
    layout!(raw::ubus_object_type, 32, 8, name => 0, id => 8, methods => 16, n_methods => 24);
    layout!(raw::ubus_object, 120, 8, avl => 0, name => 56, id => 64, path => 72, type_ => 80, subscribe_cb => 88, has_subscribers => 96, methods => 104, n_methods => 112);
    layout!(raw::ubus_request_data, 56, 8, object => 0, peer => 4, seq => 8, acl => 16, deferred => 40, fd => 44, req_fd => 48);
    layout!(raw::ubus_context, 344, 8, sock => 80, pending_timer => 96, connection_lost => 160);
}

#[test]
fn uci_layout_matches_immortalwrt_x86_64_musl() {
    layout!(raw::uci_list, 16, 8, next => 0, prev => 8);
    layout!(raw::uci_element, 32, 8, list => 0, type_ => 16, name => 24);
    layout!(raw::uci_package, 128, 8, e => 0, sections => 32, ctx => 48, has_delta => 56, uses_conf2 => 57, path => 64);
    layout!(raw::uci_section, 72, 8, e => 0, options => 32, package => 48, anonymous => 56, type_ => 64);
    layout!(raw::uci_option, 64, 8, e => 0, section => 32, type_ => 40, v => 48);
    layout!(raw::uci_ptr, 72, 8, target => 0, flags => 4, p => 8, s => 16, o => 24, last => 32, package => 40, section => 48, option => 56, value => 64);
}
