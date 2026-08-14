#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(length as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(align4(length), 0);
        bytes
    }

    fn station_message(family_id: u16, sequence: u32, include_64_bit: bool) -> Vec<u8> {
        let mut station_info = Vec::new();
        station_info.extend(encode_attribute(
            NL80211_STA_INFO_RX_BYTES,
            &123u32.to_ne_bytes(),
        ));
        station_info.extend(encode_attribute(
            NL80211_STA_INFO_TX_BYTES,
            &456u32.to_ne_bytes(),
        ));
        if include_64_bit {
            station_info.extend(encode_attribute(
                NL80211_STA_INFO_RX_BYTES64,
                &12_345_678_901u64.to_ne_bytes(),
            ));
            station_info.extend(encode_attribute(
                NL80211_STA_INFO_TX_BYTES64,
                &98_765_432_109u64.to_ne_bytes(),
            ));
        }
        station_info.extend(encode_attribute(
            NL80211_STA_INFO_RX_PACKETS,
            &100u32.to_ne_bytes(),
        ));
        station_info.extend(encode_attribute(
            NL80211_STA_INFO_TX_PACKETS,
            &200u32.to_ne_bytes(),
        ));
        station_info.extend(encode_attribute(
            NL80211_STA_INFO_CONNECTED_TIME,
            &10u32.to_ne_bytes(),
        ));
        station_info.extend(encode_attribute(
            NL80211_STA_INFO_ASSOC_AT_BOOTTIME,
            &1_000u64.to_ne_bytes(),
        ));
        let mut attributes = Vec::new();
        attributes.extend(encode_attribute(NL80211_ATTR_IFINDEX, &7u32.to_ne_bytes()));
        attributes.extend(encode_attribute(NL80211_ATTR_MAC, &[0x02, 1, 2, 3, 4, 5]));
        attributes.extend(encode_attribute(NL80211_ATTR_STA_INFO, &station_info));
        let mut payload = vec![NL80211_CMD_NEW_STATION, NL80211_GENL_VERSION, 0, 0];
        payload.extend(attributes);
        message(family_id, 0, sequence, &payload)
    }

    fn interface_message(family_id: u16, sequence: u32, ifindex: u32, iftype: u32) -> Vec<u8> {
        let mut attributes = Vec::new();
        attributes.extend(encode_attribute(
            NL80211_ATTR_IFINDEX,
            &ifindex.to_ne_bytes(),
        ));
        attributes.extend(encode_attribute(NL80211_ATTR_IFTYPE, &iftype.to_ne_bytes()));
        let mut payload = vec![NL80211_CMD_NEW_INTERFACE, NL80211_GENL_VERSION, 0, 0];
        payload.extend(attributes);
        message(family_id, 0, sequence, &payload)
    }

    #[test]
    fn station_request_is_one_dump_for_an_interface() {
        let request = station_dump_request(42, 9, 7);
        assert_eq!(read_u16(&request, 4), Some(42));
        assert_eq!(read_u16(&request, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        assert_eq!(request[NLMSG_HEADER_LEN], NL80211_CMD_GET_STATION);
        let attributes = &request[NLMSG_HEADER_LEN + GENL_HEADER_LEN..];
        let mut found = None;
        for_each_attribute(attributes, |kind, value| {
            if kind == NL80211_ATTR_IFINDEX {
                found = read_exact_u32(value);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(found, Some(7));
    }

    #[test]
    fn interface_dump_reports_ap_wds_and_mesh_types() {
        let family_id = 42;
        let sequence = 9;
        let request = interface_dump_request(family_id, sequence);
        assert_eq!(read_u16(&request, 4), Some(family_id));
        assert_eq!(read_u16(&request, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        assert_eq!(request[NLMSG_HEADER_LEN], NL80211_CMD_GET_INTERFACE);

        let mut bytes = interface_message(family_id, sequence, 7, NL80211_IFTYPE_AP);
        bytes.extend(interface_message(
            family_id,
            sequence,
            8,
            NL80211_IFTYPE_WDS,
        ));
        bytes.extend(interface_message(
            family_id,
            sequence,
            9,
            NL80211_IFTYPE_MESH_POINT,
        ));
        bytes.extend(message(NLMSG_DONE, 0, sequence, &[]));
        let parsed = parse_interface_messages(&bytes, sequence, family_id, 8).unwrap();
        assert!(parsed.done);
        assert_eq!(
            parsed.interfaces,
            vec![
                (7, NL80211_IFTYPE_AP),
                (8, NL80211_IFTYPE_WDS),
                (9, NL80211_IFTYPE_MESH_POINT),
            ]
        );
    }

    #[test]
    fn parser_prefers_64_bit_station_byte_counters() {
        let family_id = 42;
        let sequence = 9;
        let mut bytes = station_message(family_id, sequence, true);
        bytes.extend(message(NLMSG_DONE, 0, sequence, &[]));
        let parsed = parse_station_messages(&bytes, sequence, family_id, 8).unwrap();
        assert!(parsed.done);
        assert_eq!(parsed.stations.len(), 1);
        let station = parsed.stations[0];
        assert_eq!(station.counters.rx_bytes, 12_345_678_901);
        assert_eq!(station.counters.tx_bytes, 98_765_432_109);
        assert_eq!(station.rx_byte_width, StationByteCounterWidth::Bits64);
        assert_eq!(station.tx_byte_width, StationByteCounterWidth::Bits64);
        assert_eq!(station.connected_time_s, Some(10));
        assert_eq!(station.association_started_ns, Some(1_000));
    }

    #[test]
    fn parser_falls_back_to_32_bit_station_byte_counters() {
        let parsed = parse_station_messages(&station_message(42, 9, false), 9, 42, 8).unwrap();
        let station = parsed.stations[0];
        assert_eq!(station.counters.rx_bytes, 123);
        assert_eq!(station.counters.tx_bytes, 456);
        assert_eq!(station.rx_byte_width, StationByteCounterWidth::Bits32);
        assert_eq!(station.tx_byte_width, StationByteCounterWidth::Bits32);
    }

    #[test]
    fn dump_interrupt_and_overrun_are_fatal() {
        let interrupted = message(NLMSG_DONE, NLM_F_DUMP_INTR, 9, &[]);
        assert_eq!(
            parse_station_messages(&interrupted, 9, 42, 8),
            Err(Nl80211ParseError::DumpInterrupted)
        );
        let overrun = message(NLMSG_OVERRUN, 0, 9, &[]);
        assert_eq!(
            parse_station_messages(&overrun, 9, 42, 8),
            Err(Nl80211ParseError::Overrun)
        );
    }

    #[test]
    fn parses_dynamic_family_id() {
        let mut attributes = Vec::new();
        attributes.extend(encode_attribute(CTRL_ATTR_FAMILY_ID, &42u16.to_ne_bytes()));
        let mut payload = vec![CTRL_CMD_NEWFAMILY, 1, 0, 0];
        payload.extend(attributes);
        assert_eq!(
            parse_family_id_messages(&message(GENL_ID_CTRL, 0, 9, &payload), 9).unwrap(),
            Some(42)
        );
    }

    #[test]
    fn association_disappearance_or_reset_gets_a_new_generation() {
        let interface = WirelessInterface {
            ifindex: 7,
            ifname: "phy1-ap0".into(),
            bridge_ifindex: Some(10),
            vlan_id: None,
            iftype: Some(NL80211_IFTYPE_AP),
        };
        let raw = RawStationCounter {
            mac: [0x02, 1, 2, 3, 4, 5],
            ifindex: 7,
            association_started_ns: Some(1_000),
            connected_time_s: Some(10),
            counters: LinkCounters {
                rx_bytes: 100,
                tx_bytes: 200,
                rx_packets: 1,
                tx_packets: 2,
            },
            rx_byte_width: StationByteCounterWidth::Bits64,
            tx_byte_width: StationByteCounterWidth::Bits64,
        };
        let mut provider = SystemNl80211StationProvider::new(8);
        let first = provider
            .apply_generations(vec![(interface.clone(), raw)], 1, 2)
            .unwrap();
        let first_generation = first.stations[0].association_generation;
        provider.apply_generations(Vec::new(), 3, 4).unwrap();
        let second = provider
            .apply_generations(vec![(interface, raw)], 5, 6)
            .unwrap();
        assert!(second.stations[0].association_generation > first_generation);
    }

    #[test]
    fn association_marker_and_interface_mode_changes_advance_generation() {
        let mut interface = WirelessInterface {
            ifindex: 7,
            ifname: "phy1-ap0".into(),
            bridge_ifindex: Some(10),
            vlan_id: None,
            iftype: Some(NL80211_IFTYPE_AP),
        };
        let mut raw = RawStationCounter {
            mac: [0x02, 1, 2, 3, 4, 5],
            ifindex: 7,
            association_started_ns: Some(1_000),
            connected_time_s: Some(10),
            counters: LinkCounters {
                rx_bytes: 100,
                tx_bytes: 200,
                rx_packets: 1,
                tx_packets: 2,
            },
            rx_byte_width: StationByteCounterWidth::Bits64,
            tx_byte_width: StationByteCounterWidth::Bits64,
        };
        let mut provider = SystemNl80211StationProvider::new(8);
        let first = provider
            .apply_generations(vec![(interface.clone(), raw)], 1, 2)
            .unwrap();
        assert!(first.stations[0].proves_direct_client_interface());

        raw.association_started_ns = Some(2_000);
        raw.connected_time_s = Some(0);
        raw.counters.rx_bytes = 150;
        raw.counters.tx_bytes = 250;
        let reassociated = provider
            .apply_generations(vec![(interface.clone(), raw)], 3, 4)
            .unwrap();
        assert!(
            reassociated.stations[0].association_generation
                > first.stations[0].association_generation
        );

        interface.iftype = Some(NL80211_IFTYPE_WDS);
        raw.connected_time_s = Some(1);
        raw.counters.rx_bytes = 200;
        raw.counters.tx_bytes = 300;
        let wds = provider
            .apply_generations(vec![(interface.clone(), raw)], 5, 6)
            .unwrap();
        assert!(
            wds.stations[0].association_generation
                > reassociated.stations[0].association_generation
        );
        assert!(!wds.stations[0].proves_direct_client_interface());

        interface.iftype = Some(NL80211_IFTYPE_MESH_POINT);
        raw.connected_time_s = Some(2);
        raw.counters.rx_bytes = 250;
        raw.counters.tx_bytes = 350;
        let mesh = provider
            .apply_generations(vec![(interface, raw)], 7, 8)
            .unwrap();
        assert!(mesh.stations[0].association_generation > wds.stations[0].association_generation);
        assert!(!mesh.stations[0].proves_direct_client_interface());
    }
}
