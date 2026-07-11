use core::mem::{align_of, offset_of, size_of};

use lanspeed_common::{
    LanspeedConnKey, LanspeedCounters, LanspeedKey, CLIENTS_MAP_NAME, DIR_RX, DIR_TX,
    EGRESS_EARLY_PROGRAM_NAME, EGRESS_PROGRAM_NAME, INGRESS_EARLY_PROGRAM_NAME,
    INGRESS_PROGRAM_NAME, MAX_CLIENTS, MAX_CONN_TUPLES, SEEN_CONNS_MAP_NAME,
};

#[test]
fn client_key_layout_matches_bpf_abi() {
    assert_eq!(size_of::<LanspeedKey>(), 16);
    assert_eq!(align_of::<LanspeedKey>(), 4);
    assert_eq!(offset_of!(LanspeedKey, ifindex), 0);
    assert_eq!(offset_of!(LanspeedKey, vlan_or_zone), 4);
    assert_eq!(offset_of!(LanspeedKey, direction), 6);
    assert_eq!(offset_of!(LanspeedKey, reserved), 7);
    assert_eq!(offset_of!(LanspeedKey, mac), 8);
}

#[test]
fn counter_layout_matches_bpf_abi() {
    assert_eq!(size_of::<LanspeedCounters>(), 32);
    assert_eq!(align_of::<LanspeedCounters>(), 8);
    assert_eq!(offset_of!(LanspeedCounters, bytes), 0);
    assert_eq!(offset_of!(LanspeedCounters, packets), 8);
    assert_eq!(offset_of!(LanspeedCounters, last_seen), 16);
    assert_eq!(offset_of!(LanspeedCounters, tcp_conns), 24);
    assert_eq!(offset_of!(LanspeedCounters, udp_conns), 28);
}

#[test]
fn connection_key_layout_matches_legacy_c_abi() {
    assert_eq!(size_of::<LanspeedConnKey>(), 28);
    assert_eq!(align_of::<LanspeedConnKey>(), 2);
    assert_eq!(offset_of!(LanspeedConnKey, mac), 0);
    assert_eq!(offset_of!(LanspeedConnKey, proto), 6);
    assert_eq!(offset_of!(LanspeedConnKey, family), 7);
    assert_eq!(offset_of!(LanspeedConnKey, sport_be), 8);
    assert_eq!(offset_of!(LanspeedConnKey, dport_be), 10);
    assert_eq!(offset_of!(LanspeedConnKey, dst_ip), 12);
}

#[test]
fn connection_key_stores_ports_in_network_byte_order() {
    let key = LanspeedConnKey::new([0x02, 1, 2, 3, 4, 5], 6, 2, 0x1234, 0xabcd, [0; 16]);

    assert_eq!(key.sport_be.to_ne_bytes(), [0x12, 0x34]);
    assert_eq!(key.dport_be.to_ne_bytes(), [0xab, 0xcd]);
    assert_eq!(key.source_port(), 0x1234);
    assert_eq!(key.destination_port(), 0xabcd);
}

#[test]
fn directions_match_legacy_values() {
    assert_eq!(DIR_TX, 1);
    assert_eq!(DIR_RX, 2);
}

#[test]
fn shared_names_and_capacities_match_the_bpf_contract() {
    assert_eq!(CLIENTS_MAP_NAME, "lanspeed_clients");
    assert_eq!(SEEN_CONNS_MAP_NAME, "lanspeed_seen_conns");
    assert_eq!(INGRESS_PROGRAM_NAME, "lanspeed_ingress");
    assert_eq!(EGRESS_PROGRAM_NAME, "lanspeed_egress");
    assert_eq!(INGRESS_EARLY_PROGRAM_NAME, "lanspeed_ingress_early");
    assert_eq!(EGRESS_EARLY_PROGRAM_NAME, "lanspeed_egress_early");
    assert_eq!(MAX_CLIENTS, 2048);
    assert_eq!(MAX_CONN_TUPLES, 8192);
}
