use core::mem::{align_of, offset_of, size_of};

use lanspeed_common::{
    EcmCountersUpdatedEvent, EcmEventStats, EcmNssContext, FastCounterValue, LanspeedConnKey,
    LanspeedCounters, LanspeedKey, CLIENTS_MAP_NAME, DIR_RX, DIR_TX,
    ECM_FAST_COUNTERS_MAP_CAPACITY, ECM_FAST_COUNTERS_MAP_NAME, EGRESS_EARLY_PROGRAM_NAME,
    EGRESS_PROGRAM_NAME, INGRESS_EARLY_PROGRAM_NAME, INGRESS_PROGRAM_NAME, MAX_CLIENTS,
    MAX_CONN_TUPLES, ROUTED_FAST_COUNTERS_MAP_NAME, SEEN_CONNS_MAP_NAME,
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
fn ecm_nss_context_layout_matches_dirty_tracking_abi() {
    assert_eq!(size_of::<EcmNssContext>(), 8);
    assert_eq!(align_of::<EcmNssContext>(), 4);
    assert_eq!(offset_of!(EcmNssContext, depth), 0);
    assert_eq!(offset_of!(EcmNssContext, dirty), 4);
    assert_eq!(offset_of!(EcmNssContext, source_id), 5);
    assert_eq!(offset_of!(EcmNssContext, reserved), 6);
}

#[test]
fn ecm_event_layout_matches_ringbuf_abi() {
    assert_eq!(size_of::<EcmCountersUpdatedEvent>(), 24);
    assert_eq!(align_of::<EcmCountersUpdatedEvent>(), 8);
    assert_eq!(offset_of!(EcmCountersUpdatedEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(EcmCountersUpdatedEvent, sequence), 8);
    assert_eq!(offset_of!(EcmCountersUpdatedEvent, source), 16);
    assert_eq!(offset_of!(EcmCountersUpdatedEvent, round_end), 17);
    assert_eq!(offset_of!(EcmCountersUpdatedEvent, reserved), 18);
    assert_eq!(size_of::<EcmEventStats>(), 16);
    assert_eq!(align_of::<EcmEventStats>(), 8);
}

#[test]
fn fast_counter_layout_matches_stable_read_abi() {
    assert_eq!(size_of::<FastCounterValue>(), 40);
    assert_eq!(align_of::<FastCounterValue>(), 8);
    assert_eq!(offset_of!(FastCounterValue, abi_version), 0);
    assert_eq!(offset_of!(FastCounterValue, reset_generation), 4);
    assert_eq!(offset_of!(FastCounterValue, seq), 8);
    assert_eq!(offset_of!(FastCounterValue, bytes), 16);
    assert_eq!(offset_of!(FastCounterValue, packets), 24);
    assert_eq!(offset_of!(FastCounterValue, last_seen_ns), 32);
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
    assert_eq!(
        ROUTED_FAST_COUNTERS_MAP_NAME,
        "lanspeed_routed_fast_counters"
    );
    assert_eq!(ECM_FAST_COUNTERS_MAP_NAME, "lanspeed_ecm_fast_counters");
    assert_eq!(INGRESS_PROGRAM_NAME, "lanspeed_ingress");
    assert_eq!(EGRESS_PROGRAM_NAME, "lanspeed_egress");
    assert_eq!(INGRESS_EARLY_PROGRAM_NAME, "lanspeed_ingress_early");
    assert_eq!(EGRESS_EARLY_PROGRAM_NAME, "lanspeed_egress_early");
    assert_eq!(MAX_CLIENTS, 2048);
    assert_eq!(MAX_CONN_TUPLES, 8192);
    assert_eq!(ECM_FAST_COUNTERS_MAP_CAPACITY, MAX_CLIENTS * 2);
}

#[test]
fn nss_generic_netlink_abi_is_stable_and_complete() {
    use lanspeed_common::nss_genl as abi;

    assert_eq!(abi::FAMILY_NAME, "LANSPEED_NSS");
    assert_eq!(abi::VERSION, 1);
    assert_eq!(
        [
            abi::CMD_GET_CAPS,
            abi::CMD_GET_STATE,
            abi::CMD_GET_STATS,
            abi::CMD_GET_HEALTH,
            abi::CMD_IGS_STAGE,
            abi::CMD_IGS_PUBLISH,
            abi::CMD_IGS_UNPUBLISH,
            abi::CMD_IGS_DELETE,
            abi::CMD_PEER_REPLACE,
            abi::CMD_TAG_REPLACE,
            abi::CMD_TRUSTED_INGRESS_REPLACE,
        ],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    );
    assert_eq!(abi::A_HEALTHY, 25);
    assert_eq!(abi::A_PEER_REASSERT_COUNT, 26);
    assert_eq!(abi::A_IFB_NAME, 27);
    assert_eq!(abi::A_EDGE_NAME, 28);
    assert_eq!(abi::A_CONFIG, 29);
    assert_eq!(
        abi::FEATURE_IGS
            | abi::FEATURE_WIFI_PEER
            | abi::FEATURE_IGS_STATS
            | abi::FEATURE_PEER_QUERY
            | abi::FEATURE_RCU_TAGS
            | abi::FEATURE_TRUSTED_INGRESS,
        0x3f
    );
}
