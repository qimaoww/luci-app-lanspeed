use lanspeedd::{
    collectors::{
        conntrack::{NETLINK_COUNTER_SOURCE, PROCFS_COUNTER_SOURCE},
        nss::{
            direct_fallback_reason, nss_sync_reader_available, nss_sync_warnings,
            open_ecm_state_with, parse_direct_reader, DirectFallbackInput, EcmNodeMetadata,
            EcmStateFs, NssParseError, ParseLimits, RemoveOutcome, SyncAvailability,
            ECM_DIRECT_COUNTER_SOURCE, ECM_STATE_DEV_MAJOR_PATH, ECM_STATE_DEV_PATH,
            ECM_STATE_LINE_MAX, ECM_STATE_OUTPUT_MASK_PATH, ECM_STATE_TMP_DEV_PATH,
            NSS_DIRECT_SOURCE, NSS_SYNC_COLLECTOR_MODE, NSS_SYNC_PRIMARY_SOURCE,
        },
    },
    config::RateCollectorMode,
    identity::{IdentityObservation, IdentityTable, ObservationSource},
};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Cursor, Read},
};

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/../../../../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn identities(entries: &Value) -> IdentityTable {
    let mut table = IdentityTable::new(32);
    for entry in entries.as_array().unwrap() {
        table
            .observe(IdentityObservation {
                mac: entry["mac"].as_str().unwrap(),
                zone: entry["zone"].as_str(),
                interface: entry["interface"].as_str().unwrap(),
                ip: entry["ip"].as_str(),
                hostname: None,
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
    }
    table
}

fn snapshot_text(snapshot: &Value) -> String {
    let mut text = snapshot["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    text
}

#[test]
fn direct_fixture_preserves_paths_identity_direction_counters_and_warnings() {
    let fixture = fixture("lanspeed-nss-ecm-direct.json");
    let expected = &fixture["expected"];
    let table = identities(&fixture["arp_entries"]);
    let snapshot = &fixture["state_snapshots"][0];
    let parsed = parse_direct_reader(
        Cursor::new(snapshot_text(snapshot)),
        expected["source_path"].as_str().unwrap(),
        &table,
        snapshot["t_ms"].as_u64().unwrap(),
        32,
        ParseLimits::default(),
    )
    .unwrap();

    assert_eq!(ECM_STATE_DEV_PATH, "/dev/ecm_state");
    assert_eq!(
        ECM_STATE_DEV_MAJOR_PATH,
        "/sys/kernel/debug/ecm/ecm_state/state_dev_major"
    );
    assert_eq!(
        ECM_STATE_OUTPUT_MASK_PATH,
        "/sys/kernel/debug/ecm/ecm_state/state_file_output_mask"
    );
    assert_eq!(ECM_STATE_TMP_DEV_PATH, "/dev/lanspeed-ecm-state");
    assert_eq!(ECM_STATE_LINE_MAX, 1024);
    assert_eq!(parsed.source_path, expected["source_path"]);
    assert_eq!(parsed.counter_source, ECM_DIRECT_COUNTER_SOURCE);
    assert_eq!(
        parsed.counter_source,
        "ecm_state_adv_stats_from_to_data_total"
    );
    assert_eq!(parsed.stats.entries_seen, expected["flows_seen"]);
    assert_eq!(parsed.stats.entries_matched, expected["flows_matched"]);
    assert_eq!(parsed.stats.skipped_no_arp, expected["skipped_no_arp"]);
    assert_eq!(parsed.stats.malformed_lines, expected["parse_errors"]);
    assert_eq!(
        parsed.clients.len(),
        expected["client_count"].as_u64().unwrap() as usize
    );
    assert_eq!(parsed.clients[0].identity_key, expected["first_identity"]);
    assert_eq!(
        (parsed.clients[0].tx_bytes, parsed.clients[0].rx_bytes),
        (1_000_000, 2_000_000)
    );
    assert_eq!(
        (parsed.clients[1].tx_bytes, parsed.clients[1].rx_bytes),
        (500_000, 100_000)
    );
    assert_eq!(parsed.clients[0].tcp_conns, 1);
    assert_eq!(parsed.clients[1].udp_conns, 1);
    assert!(parsed.warnings.contains(&"nss_ecm_direct_parse_errors"));
    assert!(parsed
        .warnings
        .contains(&"skip_nss_ecm_direct_flow_without_lan_identity"));
    assert!(!parsed.warnings.contains(&"nss_direct_no_data"));
    assert_eq!(NSS_DIRECT_SOURCE, expected["primary_source"]);
}

#[test]
fn nat_ip_then_node_mac_mapping_reuses_identity_and_keeps_lan_view_direction() {
    let entries = serde_json::json!([
        {"ip":"10.77.0.102","mac":"02:bb:cc:00:00:03","interface":"br-lan","zone":"lan"},
        {"ip":"10.77.0.103","mac":"02:bb:cc:00:00:04","interface":"br-lan","zone":"lan"}
    ]);
    let table = identities(&entries);
    let text = concat!(
        "conns.conn.70.serial=70\n",
        "conns.conn.70.sip_address=198.51.100.20\n",
        "conns.conn.70.sip_address_nat=10.77.0.102\n",
        "conns.conn.70.dip_address=203.0.113.10\n",
        "conns.conn.70.snode_address=00:00:00:00:00:00\n",
        "conns.conn.70.snode_address_nat=02:bb:cc:00:00:03\n",
        "conns.conn.70.protocol=6\n",
        "conns.conn.70.adv_stats.from_data_total=1500000\n",
        "conns.conn.70.adv_stats.to_data_total=3000000\n",
        "conns.conn.71.serial=71\n",
        "conns.conn.71.sip_address=203.0.113.11\n",
        "conns.conn.71.dip_address=198.51.100.21\n",
        "conns.conn.71.dnode_address=02:bb:cc:00:00:04\n",
        "conns.conn.71.protocol=17\n",
        "conns.conn.71.adv_stats.from_data_total=900000\n",
        "conns.conn.71.adv_stats.to_data_total=250000\n",
    );
    let parsed = parse_direct_reader(
        Cursor::new(text),
        ECM_STATE_DEV_PATH,
        &table,
        101_000,
        8,
        ParseLimits::default(),
    )
    .unwrap();

    assert_eq!(parsed.clients[0].identity_key, "02:bb:cc:00:00:03@lan");
    assert_eq!(
        (parsed.clients[0].tx_bytes, parsed.clients[0].rx_bytes),
        (1_500_000, 3_000_000)
    );
    assert_eq!(parsed.clients[0].ips, ["10.77.0.102"]);
    assert_eq!(parsed.clients[1].identity_key, "02:bb:cc:00:00:04@lan");
    assert_eq!(
        (parsed.clients[1].tx_bytes, parsed.clients[1].rx_bytes),
        (250_000, 900_000)
    );
    assert_eq!(parsed.stats.src_lan_flows, 1);
    assert_eq!(parsed.stats.dst_lan_flows, 1);
}

#[test]
fn ip_owner_wins_over_disagreeing_ecm_mac_and_both_lan_is_not_attributed() {
    let entries = serde_json::json!([
        {"ip":"10.77.0.100","mac":"02:aa:00:00:00:01","interface":"br-lan","zone":"lan"},
        {"ip":"10.77.0.101","mac":"02:aa:00:00:00:02","interface":"br-lan","zone":"lan"}
    ]);
    let table = identities(&entries);
    let text = concat!(
        "conns.conn.1.sip_address=10.77.0.100\n",
        "conns.conn.1.dip_address=1.1.1.1\n",
        "conns.conn.1.snode_address=02:ff:00:00:00:09\n",
        "conns.conn.1.protocol=6\n",
        "conns.conn.1.adv_stats.from_data_total=10\n",
        "conns.conn.1.adv_stats.to_data_total=20\n",
        "conns.conn.2.sip_address=10.77.0.100\n",
        "conns.conn.2.dip_address=10.77.0.101\n",
        "conns.conn.2.adv_stats.from_data_total=30\n",
        "conns.conn.2.adv_stats.to_data_total=40\n",
    );
    let parsed = parse_direct_reader(
        Cursor::new(text),
        ECM_STATE_DEV_PATH,
        &table,
        1,
        8,
        ParseLimits::default(),
    )
    .unwrap();
    assert_eq!(parsed.clients.len(), 1);
    assert_eq!(parsed.clients[0].identity_key, "02:aa:00:00:00:01@lan");
    assert_eq!(
        (parsed.clients[0].tx_bytes, parsed.clients[0].rx_bytes),
        (10, 20)
    );
    assert_eq!(parsed.stats.both_lan_flows, 1);
}

#[test]
fn endpoint_family_stats_follow_the_address_that_matched_the_shared_identity() {
    let entries = serde_json::json!([
        {"ip":"10.77.0.100","mac":"02:aa:00:00:00:01","interface":"br-lan","zone":"lan"},
        {"ip":"240e:abc:1234::100","mac":"02:aa:00:00:00:01","interface":"br-lan","zone":"lan"}
    ]);
    let table = identities(&entries);
    let text = concat!(
        "conns.conn.80.sip_address=240E:0ABC:1234:0000:0000:0000:0000:0100\n",
        "conns.conn.80.dip_address=2606:4700:4700::1111\n",
        "conns.conn.80.protocol=6\n",
        "conns.conn.80.adv_stats.from_data_total=10\n",
        "conns.conn.80.adv_stats.to_data_total=20\n",
    );
    let parsed = parse_direct_reader(
        Cursor::new(text),
        "fixture",
        &table,
        1,
        8,
        ParseLimits::default(),
    )
    .unwrap();
    assert_eq!(parsed.clients[0].identity_key, "02:aa:00:00:00:01@lan");
    assert_eq!(parsed.stats.ipv4_lan_flows, 0);
    assert_eq!(parsed.stats.ipv6_lan_flows, 1);
}

#[test]
fn parser_is_bounded_tolerates_unknown_fields_and_strictly_rejects_bad_required_values() {
    let entries = serde_json::json!([
        {"ip":"192.168.1.2","mac":"02:00:00:00:00:02","interface":"br-lan","zone":"lan"}
    ]);
    let table = identities(&entries);
    let mut text = String::new();
    text.push_str("conns.conn.90.sip_address=192.168.1.2\n");
    text.push_str("conns.conn.90.unknown.future.field=accepted\n");
    text.push_str("conns.conn.90.protocol=6tail\n");
    text.push_str("conns.conn.90.adv_stats.from_data_total=10tail\n");
    text.push_str("conns.conn.91.sip_address=192.168.1.2\n");
    text.push_str("conns.conn.91.protocol=17\n");
    text.push_str("conns.conn.91.adv_stats.from_data_total=20\n");
    text.push_str("conns.conn.91.adv_stats.to_data_total=30\n");
    text.push_str("conns.conn.92.sip_address=192.168.1.2\n");
    text.push_str("conns.conn.92.adv_stats.from_data_total=40\n");
    text.push_str("conns.conn.92.adv_stats.from_data_total=invalid\n");
    text.push_str(&"x".repeat(ECM_STATE_LINE_MAX + 1));
    text.push('\n');
    let parsed = parse_direct_reader(
        Cursor::new(text),
        "fixture",
        &table,
        9,
        8,
        ParseLimits::new(64, 8),
    )
    .unwrap();
    assert_eq!(parsed.stats.entries_seen, 3);
    assert_eq!(parsed.stats.entries_matched, 1);
    assert_eq!(parsed.stats.malformed_lines, 4);
    assert_eq!(parsed.clients[0].udp_conns, 1);
    assert_eq!(
        (parsed.clients[0].tx_bytes, parsed.clients[0].rx_bytes),
        (20, 30)
    );

    let line_limited =
        "conns.conn.1.sip_address=192.168.1.2\nconns.conn.1.adv_stats.from_data_total=1\n";
    assert_eq!(
        parse_direct_reader(
            Cursor::new(line_limited),
            "fixture",
            &table,
            1,
            8,
            ParseLimits::new(1, 8),
        )
        .unwrap_err(),
        NssParseError::LineLimit(1)
    );

    let two_flows = concat!(
        "conns.conn.1.sip_address=192.168.1.2\n",
        "conns.conn.1.adv_stats.from_data_total=1\n",
        "conns.conn.2.sip_address=192.168.1.2\n",
        "conns.conn.2.adv_stats.from_data_total=2\n",
    );
    assert_eq!(
        parse_direct_reader(
            Cursor::new(two_flows),
            "fixture",
            &table,
            1,
            8,
            ParseLimits::new(16, 1),
        )
        .unwrap_err(),
        NssParseError::ConnectionLimit(1)
    );
}

#[test]
fn parser_caps_all_consumed_bytes_including_an_oversized_unterminated_line() {
    let table = IdentityTable::new(1);
    let input = vec![b'x'; ECM_STATE_LINE_MAX * 8];
    assert_eq!(
        parse_direct_reader(
            Cursor::new(input),
            "fixture",
            &table,
            1,
            1,
            ParseLimits::new(64, 8).with_max_bytes(ECM_STATE_LINE_MAX + 17),
        )
        .unwrap_err(),
        NssParseError::ByteLimit(ECM_STATE_LINE_MAX + 17)
    );
}

#[test]
fn parser_requires_bounded_u64_serials_and_rejects_noncontiguous_reappearance() {
    let entries = serde_json::json!([
        {"ip":"192.168.1.2","mac":"02:00:00:00:00:02","interface":"br-lan","zone":"lan"}
    ]);
    let table = identities(&entries);
    let text = concat!(
        "conns.conn.alpha.sip_address=192.168.1.2\n",
        "conns.conn.18446744073709551616.sip_address=192.168.1.2\n",
        "conns.conn.100.sip_address=192.168.1.2\n",
        "conns.conn.100.adv_stats.from_data_total=10\n",
        "conns.conn.101.sip_address=203.0.113.1\n",
        "conns.conn.101.adv_stats.from_data_total=20\n",
        "conns.conn.100.adv_stats.to_data_total=30\n",
    );
    let parsed = parse_direct_reader(
        Cursor::new(text),
        "fixture",
        &table,
        1,
        8,
        ParseLimits::default(),
    )
    .unwrap();
    assert_eq!(parsed.stats.entries_seen, 2);
    assert_eq!(parsed.stats.entries_matched, 1);
    assert_eq!(parsed.stats.malformed_lines, 3);
    assert_eq!(
        (parsed.clients[0].tx_bytes, parsed.clients[0].rx_bytes),
        (10, 0)
    );
}

#[test]
fn duplicate_known_fields_invalidate_the_flow_while_duplicate_unknown_fields_are_tolerated() {
    let entries = serde_json::json!([
        {"ip":"192.168.1.2","mac":"02:00:00:00:00:02","interface":"br-lan","zone":"lan"}
    ]);
    let table = identities(&entries);
    let text = concat!(
        "conns.conn.110.sip_address=192.168.1.2\n",
        "conns.conn.110.sip_address=192.168.1.2\n",
        "conns.conn.110.adv_stats.from_data_total=10\n",
        "conns.conn.111.sip_address=192.168.1.2\n",
        "conns.conn.111.future_field=one\n",
        "conns.conn.111.future_field=two\n",
        "conns.conn.111.adv_stats.from_data_total=20\n",
        "conns.conn.112.serial=999\n",
        "conns.conn.112.sip_address=192.168.1.2\n",
        "conns.conn.112.adv_stats.from_data_total=30\n",
    );
    let parsed = parse_direct_reader(
        Cursor::new(text),
        "fixture",
        &table,
        1,
        8,
        ParseLimits::default(),
    )
    .unwrap();
    assert_eq!(parsed.stats.entries_seen, 3);
    assert_eq!(parsed.stats.entries_matched, 1);
    assert_eq!(parsed.stats.malformed_lines, 2);
    assert_eq!(parsed.clients[0].tx_bytes, 20);
}

#[derive(Debug)]
struct MockReader {
    id: u64,
    cursor: Cursor<Vec<u8>>,
}

impl Read for MockReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(buffer)
    }
}

#[derive(Default)]
struct MockFs {
    opens: Vec<(String, i32)>,
    replies: HashMap<String, VecDeque<io::Result<Vec<u8>>>>,
    open_metadata: HashMap<String, VecDeque<EcmNodeMetadata>>,
    reader_metadata: HashMap<u64, EcmNodeMetadata>,
    current_nodes: HashMap<String, EcmNodeMetadata>,
    next_reader_id: u64,
    next_inode: u64,
    nodes: Vec<(String, u32, u32, u32)>,
    node_error: Option<i32>,
    unlinks: Vec<String>,
    cleared_nonblock: Vec<u64>,
    clear_nonblock_error: Option<i32>,
    replace_before_remove: Option<EcmNodeMetadata>,
    lock_calls: usize,
    unlock_calls: usize,
    locked: bool,
}

impl MockFs {
    fn reply(mut self, path: &str, reply: io::Result<Vec<u8>>) -> Self {
        self.replies
            .entry(path.to_owned())
            .or_default()
            .push_back(reply);
        self
    }

    fn reply_with_metadata(mut self, path: &str, bytes: &[u8], metadata: EcmNodeMetadata) -> Self {
        self = self.reply(path, Ok(bytes.to_vec()));
        self.open_metadata
            .entry(path.to_owned())
            .or_default()
            .push_back(metadata);
        self
    }

    fn default_metadata(&self, path: &str) -> EcmNodeMetadata {
        if path == ECM_STATE_DEV_PATH || path == ECM_STATE_TMP_DEV_PATH {
            char_metadata(1, 10, 240, 0)
        } else {
            regular_metadata(1, 20)
        }
    }
}

impl EcmStateFs for MockFs {
    type Reader = MockReader;

    fn open(&mut self, path: &str, flags: i32) -> io::Result<Self::Reader> {
        self.opens.push((path.to_owned(), flags));
        let bytes = self
            .replies
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| Err(io::Error::from_raw_os_error(libc::ENOENT)))?;
        self.next_reader_id = self.next_reader_id.saturating_add(1);
        let id = self.next_reader_id;
        let metadata = self
            .open_metadata
            .get_mut(path)
            .and_then(VecDeque::pop_front)
            .or_else(|| self.current_nodes.get(path).copied())
            .unwrap_or_else(|| self.default_metadata(path));
        self.reader_metadata.insert(id, metadata);
        Ok(MockReader {
            id,
            cursor: Cursor::new(bytes),
        })
    }

    fn mknod_char(&mut self, path: &str, mode: u32, major: u32, minor: u32) -> io::Result<()> {
        self.nodes.push((path.to_owned(), mode, major, minor));
        match self.node_error {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => {
                self.next_inode = self.next_inode.saturating_add(1);
                self.current_nodes.insert(
                    path.to_owned(),
                    char_metadata(7, 1_000 + self.next_inode, major, minor),
                );
                Ok(())
            }
        }
    }

    fn fstat(&mut self, reader: &Self::Reader) -> io::Result<EcmNodeMetadata> {
        self.reader_metadata
            .get(&reader.id)
            .copied()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
    }

    fn lstat(&mut self, path: &str) -> io::Result<EcmNodeMetadata> {
        self.current_nodes
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn clear_nonblock(&mut self, reader: &Self::Reader) -> io::Result<()> {
        self.cleared_nonblock.push(reader.id);
        match self.clear_nonblock_error {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => Ok(()),
        }
    }

    fn lock_device_dir(&mut self) -> io::Result<()> {
        self.lock_calls = self.lock_calls.saturating_add(1);
        self.locked = true;
        Ok(())
    }

    fn unlock_device_dir(&mut self) -> io::Result<()> {
        self.unlock_calls = self.unlock_calls.saturating_add(1);
        self.locked = false;
        Ok(())
    }

    fn remove_if_same(
        &mut self,
        path: &str,
        expected: EcmNodeMetadata,
    ) -> io::Result<RemoveOutcome> {
        assert!(
            self.locked,
            "conditional removal must run under the /dev lock"
        );
        if let Some(replacement) = self.replace_before_remove.take() {
            self.current_nodes.insert(path.to_owned(), replacement);
        }
        match self.current_nodes.get(path).copied() {
            Some(current) if current == expected => {
                self.unlinks.push(path.to_owned());
                self.current_nodes.remove(path);
                Ok(RemoveOutcome::Removed)
            }
            _ => Ok(RemoveOutcome::Changed),
        }
    }
}

fn char_metadata(dev: u64, ino: u64, major: u32, minor: u32) -> EcmNodeMetadata {
    EcmNodeMetadata {
        mode: libc::S_IFCHR,
        dev,
        ino,
        rdev: libc::makedev(major, minor),
    }
}

fn regular_metadata(dev: u64, ino: u64) -> EcmNodeMetadata {
    EcmNodeMetadata {
        mode: libc::S_IFREG,
        dev,
        ino,
        rdev: 0,
    }
}

#[test]
fn state_open_is_read_only_cloexec_and_only_unlinks_a_node_created_by_this_attempt() {
    let mut primary = MockFs::default().reply(ECM_STATE_DEV_PATH, Ok(b"state".to_vec()));
    let opened = open_ecm_state_with(&mut primary).unwrap();
    assert_eq!(opened.source_path, ECM_STATE_DEV_PATH);
    assert_eq!(opened.state_major, 0);
    assert_eq!(primary.opens.len(), 2);
    assert!(primary.opens.iter().all(|(_, flags)| {
        flags & libc::O_ACCMODE == libc::O_RDONLY
            && flags & libc::O_CLOEXEC != 0
            && flags & libc::O_NOFOLLOW != 0
            && flags & libc::O_NONBLOCK != 0
    }));
    assert_eq!(primary.cleared_nonblock.len(), 1);
    assert_eq!((primary.lock_calls, primary.unlock_calls), (1, 1));
    assert!(primary.nodes.is_empty());
    assert!(primary.unlinks.is_empty());

    let mut fallback = MockFs::default()
        .reply(
            ECM_STATE_DEV_PATH,
            Err(io::Error::from_raw_os_error(libc::ENOENT)),
        )
        .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"240\n".to_vec()))
        .reply(ECM_STATE_TMP_DEV_PATH, Ok(b"state".to_vec()));
    let opened = open_ecm_state_with(&mut fallback).unwrap();
    assert_eq!(opened.source_path, ECM_STATE_TMP_DEV_PATH);
    assert_eq!(opened.state_major, 240);
    assert_eq!(
        fallback.nodes,
        [(ECM_STATE_TMP_DEV_PATH.to_owned(), 0o600, 240, 0)]
    );
    assert_eq!(fallback.unlinks, [ECM_STATE_TMP_DEV_PATH]);
    assert!(fallback.opens.iter().all(|(_, flags)| {
        flags & libc::O_ACCMODE == libc::O_RDONLY
            && flags & libc::O_CLOEXEC != 0
            && flags & libc::O_NOFOLLOW != 0
            && flags & libc::O_NONBLOCK != 0
    }));
    assert_eq!(fallback.cleared_nonblock.len(), 1);
    assert_eq!((fallback.lock_calls, fallback.unlock_calls), (1, 1));

    let mut existing = MockFs {
        node_error: Some(libc::EEXIST),
        ..MockFs::default()
    }
    .reply(
        ECM_STATE_DEV_PATH,
        Err(io::Error::from_raw_os_error(libc::ENOENT)),
    )
    .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"240\n".to_vec()));
    let error = open_ecm_state_with(&mut existing).unwrap_err();
    assert_eq!(error.errno(), Some(libc::EEXIST));
    assert!(
        existing.unlinks.is_empty(),
        "pre-existing temp node must survive"
    );
}

#[test]
fn state_open_rejects_symlink_regular_fifo_and_wrong_rdev_without_blocking() {
    let mut symlink = MockFs::default()
        .reply(
            ECM_STATE_DEV_PATH,
            Err(io::Error::from_raw_os_error(libc::ELOOP)),
        )
        .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"240\n".to_vec()));
    let error = open_ecm_state_with(&mut symlink).unwrap_err();
    assert_eq!(error.errno(), Some(libc::ELOOP));
    assert!(symlink.nodes.is_empty());

    for mode in [libc::S_IFREG, libc::S_IFIFO] {
        let metadata = EcmNodeMetadata {
            mode,
            dev: 1,
            ino: 2,
            rdev: 0,
        };
        let mut fs = MockFs::default().reply_with_metadata(ECM_STATE_DEV_PATH, b"bad", metadata);
        let error = open_ecm_state_with(&mut fs).unwrap_err();
        assert_eq!(error.errno(), Some(libc::ENODEV));
        assert!(fs.nodes.is_empty());
        assert!(fs.cleared_nonblock.is_empty());
    }

    let mut mismatched_primary = MockFs::default()
        .reply_with_metadata(ECM_STATE_DEV_PATH, b"state", char_metadata(1, 2, 241, 0))
        .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"240\n".to_vec()));
    let error = open_ecm_state_with(&mut mismatched_primary).unwrap_err();
    assert_eq!(error.errno(), Some(libc::ENODEV));
    assert!(mismatched_primary.nodes.is_empty());

    let mut wrong_rdev = MockFs::default()
        .reply(
            ECM_STATE_DEV_PATH,
            Err(io::Error::from_raw_os_error(libc::ENOENT)),
        )
        .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"240\n".to_vec()))
        .reply_with_metadata(
            ECM_STATE_TMP_DEV_PATH,
            b"state",
            char_metadata(7, 1_001, 241, 0),
        );
    let error = open_ecm_state_with(&mut wrong_rdev).unwrap_err();
    assert_eq!(error.errno(), Some(libc::ENODEV));
    assert_eq!(wrong_rdev.unlinks, [ECM_STATE_TMP_DEV_PATH]);
}

#[test]
fn owned_temp_cleanup_never_unlinks_a_replaced_inode_or_symlink() {
    for replacement in [
        regular_metadata(9, 9_999),
        EcmNodeMetadata {
            mode: libc::S_IFLNK,
            dev: 9,
            ino: 10_000,
            rdev: 0,
        },
    ] {
        let mut fs = MockFs::default()
            .reply(
                ECM_STATE_DEV_PATH,
                Err(io::Error::from_raw_os_error(libc::ENOENT)),
            )
            .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"240\n".to_vec()))
            .reply(ECM_STATE_TMP_DEV_PATH, Ok(b"state".to_vec()));
        fs.replace_before_remove = Some(replacement);
        let error = open_ecm_state_with(&mut fs).unwrap_err();
        assert_eq!(error.errno(), Some(libc::ESTALE));
        assert!(fs.unlinks.is_empty());
        assert_eq!(fs.current_nodes[ECM_STATE_TMP_DEV_PATH], replacement);
        assert_eq!((fs.lock_calls, fs.unlock_calls), (1, 1));
    }
}

#[test]
fn owned_temp_is_cleaned_when_clearing_nonblock_fails() {
    let mut fs = MockFs {
        clear_nonblock_error: Some(libc::EIO),
        ..MockFs::default()
    }
    .reply(
        ECM_STATE_DEV_PATH,
        Err(io::Error::from_raw_os_error(libc::ENOENT)),
    )
    .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"240\n".to_vec()))
    .reply(ECM_STATE_TMP_DEV_PATH, Ok(b"state".to_vec()));
    let error = open_ecm_state_with(&mut fs).unwrap_err();
    assert_eq!(error.errno(), Some(libc::EIO));
    assert_eq!(fs.unlinks, [ECM_STATE_TMP_DEV_PATH]);
}

#[test]
fn failed_owned_temp_open_is_cleaned_and_major_metadata_is_strict_and_bounded() {
    let mut failed_open = MockFs::default()
        .reply(
            ECM_STATE_DEV_PATH,
            Err(io::Error::from_raw_os_error(libc::ENOENT)),
        )
        .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(b"241\n".to_vec()))
        .reply(
            ECM_STATE_TMP_DEV_PATH,
            Err(io::Error::from_raw_os_error(libc::EACCES)),
        );
    let error = open_ecm_state_with(&mut failed_open).unwrap_err();
    assert_eq!(error.errno(), Some(libc::EACCES));
    assert_eq!(failed_open.unlinks, [ECM_STATE_TMP_DEV_PATH]);

    for invalid in [b"0\n".as_slice(), b"12tail\n", b"4294967296\n", &[b'9'; 33]] {
        let mut fs = MockFs::default()
            .reply(
                ECM_STATE_DEV_PATH,
                Err(io::Error::from_raw_os_error(libc::ENOENT)),
            )
            .reply(ECM_STATE_DEV_MAJOR_PATH, Ok(invalid.to_vec()));
        let error = open_ecm_state_with(&mut fs).unwrap_err();
        assert_eq!(error.errno(), Some(libc::EINVAL));
        assert!(fs.nodes.is_empty());
        assert!(fs.unlinks.is_empty());
    }

    let mut missing_metadata = MockFs::default().reply(
        ECM_STATE_DEV_PATH,
        Err(io::Error::from_raw_os_error(libc::EACCES)),
    );
    let error = open_ecm_state_with(&mut missing_metadata).unwrap_err();
    assert_eq!(error.primary_errno, Some(libc::EACCES));
    assert_eq!(
        error.errno(),
        Some(libc::EACCES),
        "legacy evidence retains the primary state-device errno when major metadata is absent"
    );
}

#[test]
fn sync_fixtures_keep_conntrack_counter_sources_warning_text_and_accounting_fallback() {
    let sync = fixture("lanspeed-nss-ecm-sync.json");
    let sync_facts = SyncAvailability {
        enable_conntrack_fallback: sync["config"]["enable_conntrack_fallback"]
            .as_bool()
            .unwrap(),
        bpf_full_available: sync["config"]["bpf_full_available"].as_bool().unwrap(),
        nf_conntrack_acct: sync["probe"]["nf_conntrack_acct"].as_bool().unwrap(),
        nss_present: sync["probe"]["nss_present"].as_bool().unwrap(),
        nss_ecm_active: sync["probe"]["nss_ecm_active"].as_bool().unwrap(),
        nss_ppe_active: sync["probe"]["nss_ppe_active"].as_bool().unwrap(),
    };
    assert!(nss_sync_reader_available(sync_facts));
    assert_eq!(NSS_SYNC_PRIMARY_SOURCE, "nss_conntrack_sync");
    assert_eq!(NSS_SYNC_COLLECTOR_MODE, "conntrack_ecm_sync");
    assert_eq!(
        [NETLINK_COUNTER_SOURCE, PROCFS_COUNTER_SOURCE],
        [
            "ctnetlink_conntrack_acct_orig_reply_bytes",
            "procfs_conntrack_acct_orig_reply_bytes"
        ]
    );
    assert_eq!(
        nss_sync_warnings(sync_facts),
        ["nss_ecm_sync_cadence", "nss_prefers_conntrack_sync"]
    );

    let fallback = fixture("lanspeed-nss-ecm-sync-bpf-fallback.json");
    let unavailable = SyncAvailability {
        enable_conntrack_fallback: fallback["config"]["enable_conntrack_fallback"]
            .as_bool()
            .unwrap(),
        bpf_full_available: fallback["config"]["bpf_full_available"].as_bool().unwrap(),
        nf_conntrack_acct: fallback["probe"]["nf_conntrack_acct"].as_bool().unwrap(),
        nss_present: fallback["probe"]["nss_present"].as_bool().unwrap(),
        nss_ecm_active: fallback["probe"]["nss_ecm_active"].as_bool().unwrap(),
        nss_ppe_active: fallback["probe"]["nss_ppe_active"].as_bool().unwrap(),
    };
    assert!(!nss_sync_reader_available(unavailable));
    assert_eq!(nss_sync_warnings(unavailable), ["conntrack_acct_disabled"]);
}

#[test]
fn direct_fallback_reason_preserves_the_legacy_status_strings() {
    let base = DirectFallbackInput {
        state_readable: true,
        overlay_enabled: false,
        rate_mode: RateCollectorMode::Auto,
        dae_runtime_prefers_bpf: false,
    };
    assert_eq!(
        direct_fallback_reason(DirectFallbackInput {
            overlay_enabled: true,
            ..base
        }),
        ""
    );
    assert_eq!(
        direct_fallback_reason(DirectFallbackInput {
            state_readable: false,
            ..base
        }),
        "state_unavailable_or_unreadable"
    );
    assert_eq!(
        direct_fallback_reason(DirectFallbackInput {
            rate_mode: RateCollectorMode::Bpf,
            ..base
        }),
        "collector_mode_bpf"
    );
    assert_eq!(
        direct_fallback_reason(DirectFallbackInput {
            rate_mode: RateCollectorMode::NssConntrackSync,
            ..base
        }),
        "collector_mode_nss_conntrack_sync"
    );
    assert_eq!(
        direct_fallback_reason(DirectFallbackInput {
            dae_runtime_prefers_bpf: true,
            ..base
        }),
        "dae_runtime_prefers_bpf"
    );
    assert_eq!(direct_fallback_reason(base), "not_selected");
}
