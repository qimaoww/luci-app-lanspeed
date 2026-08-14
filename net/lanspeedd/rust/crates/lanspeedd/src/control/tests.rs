use super::*;

fn client(identity_key: &str, ip: &str) -> Client {
    Client {
        mac: identity_key.split('@').next().unwrap().into(),
        identity_key: identity_key.into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec![ip.into()],
        hostname: None,
        rx_bps: 0,
        tx_bps: 0,
        last_seen: 0,
        sample_ms: None,
        rx_bytes: None,
        tx_bytes: None,
        collector_mode: "bpf".into(),
        confidence: crate::model::Confidence::High,
        warnings: vec![],
        tcp_conns: None,
        udp_conns: None,
        udp_dns_conns: None,
        udp_other_conns: None,
        rate_meta: {
            #[cfg(feature = "nss-platform")]
            {
                Some(crate::model::ClientRateMeta {
                    attachment: Some(crate::model::RateAttachment {
                        kind: crate::model::AttachmentKind::Ethernet,
                        ifname: Some("br-lan".into()),
                        trust: crate::model::AttachmentTrust::ObservedExclusive,
                    }),
                    ..Default::default()
                })
            }
            #[cfg(not(feature = "nss-platform"))]
            {
                None
            }
        },
        control: None,
    }
}

fn set_client_interface(client: &mut Client, interface: &str) {
    client.interface = interface.into();
    #[cfg(feature = "nss-platform")]
    if let Some(attachment) = client
        .rate_meta
        .as_mut()
        .and_then(|meta| meta.attachment.as_mut())
    {
        attachment.ifname = Some(interface.into());
    }
}

fn manager() -> ControlManager {
    ControlManager {
        rules: BTreeMap::new(),
        live: BTreeMap::new(),
        result: ApplyResult::ready(),
        lan_device: "br-lan".into(),
        control_devices: BTreeSet::from(["br-lan".into()]),
        preempted_upload_devices: BTreeSet::new(),
        dae_upload_devices: BTreeSet::new(),
        dae_topology_known: false,
        dae_active: false,
        local_prefixes: Vec::new(),
        local_prefixes_ready: false,
        last_local_prefix_refresh: None,
        max_rate_bps: platform::max_rate_bps(),
        dirty: false,
        #[cfg(feature = "nss-platform")]
        nss: NssControlState::default(),
    }
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_control_diagnostics_aggregate_executors_without_identity() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 100_000_000,
            internet_disabled: true,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    manager.live.insert(
        identity.into(),
        LiveClient {
            identity_key: identity.into(),
            interface: Some("edge0".into()),
            ips: vec!["192.0.2.9".parse().unwrap()],
            ambiguous: false,
        },
    );
    manager.result.state = "verified".into();
    manager
        .result
        .verified_directions
        .insert(identity.into(), NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD);
    manager
        .result
        .nss_verified_directions
        .insert(identity.into(), NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD);
    manager
        .result
        .cpu_verified_directions
        .insert(identity.into(), NSS_CPU_DOWNLOAD);

    let diagnostics = manager.nss_control_diagnostics();
    assert_eq!(diagnostics["state"], "verified");
    assert_eq!(diagnostics["configured_clients"], 1);
    assert_eq!(diagnostics["effective_clients"], 1);
    assert_eq!(diagnostics["required_directions"], 2);
    assert_eq!(diagnostics["verified_directions"], 2);
    assert_eq!(diagnostics["nss_verified_directions"], 2);
    assert_eq!(diagnostics["cpu_verified_directions"], 1);
    assert_eq!(diagnostics["block_active_clients"], 1);
    assert!(!diagnostics.to_string().contains(identity));
    assert!(!diagnostics.to_string().contains("192.0.2.9"));
    assert!(!diagnostics.to_string().contains("edge0"));
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_control_diagnostics_never_treat_queue_overflow_as_verified() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    manager.live.insert(
        identity.into(),
        LiveClient {
            identity_key: identity.into(),
            interface: Some("edge0".into()),
            ips: vec!["192.0.2.9".parse().unwrap()],
            ambiguous: false,
        },
    );
    manager.result.state = "verified".into();
    manager
        .result
        .verification_failures
        .insert(identity.into(), "queue_overflow".into());

    let diagnostics = manager.nss_control_diagnostics();
    assert_eq!(diagnostics["state"], "error");
    assert_eq!(diagnostics["reason_code"], "nss_control_executor_failed");
    assert_eq!(diagnostics["detail_code"], "queue_overflow");
    assert_eq!(diagnostics["queue_overflow_clients"], 1);
    assert_eq!(diagnostics["effective_clients"], 0);
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_reload_inherits_only_an_unchanged_control_plan() {
    let identity = "02:00:00:00:00:01@lan";
    let rule = ControlRule {
        identity_key: identity.into(),
        mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
        upload_bps: 10_000_000,
        download_bps: 100_000_000,
        internet_disabled: false,
        class_minor: FIRST_CLASS_MINOR,
    };
    let mut current = manager();
    current.rules.insert(identity.into(), rule.clone());
    current.live.insert(
        identity.into(),
        LiveClient {
            identity_key: identity.into(),
            interface: Some("edge0".into()),
            ips: vec!["192.0.2.9".parse().unwrap()],
            ambiguous: false,
        },
    );
    current.result.state = "verified".into();
    current.dirty = false;
    current
        .nss_proven_directions
        .insert(identity.into(), NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD);
    current
        .nss_path_ready_directions
        .insert(identity.into(), NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD);
    current
        .nss_cpu_directions
        .insert(identity.into(), NSS_CPU_DOWNLOAD);
    current
        .nss_attachment_generations
        .insert(identity.into(), ("edge0".into(), 7));

    let mut candidate = manager();
    candidate.rules.insert(identity.into(), rule.clone());
    candidate.inherit_nss_reload_state(&current);
    assert_eq!(candidate.result.state, "verified");
    assert_eq!(candidate.live, current.live);
    assert_eq!(
        candidate.nss_proven_directions.get(identity),
        Some(&(NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD))
    );
    assert_eq!(
        candidate.nss_cpu_directions.get(identity),
        Some(&NSS_CPU_DOWNLOAD)
    );
    assert!(candidate.nss_reload_attachment_rebase_pending);
    assert!(!candidate.dirty);

    let mut changed_rule = manager();
    changed_rule.rules.insert(
        identity.into(),
        ControlRule {
            upload_bps: 20_000_000,
            ..rule.clone()
        },
    );
    changed_rule.inherit_nss_reload_state(&current);
    assert_eq!(changed_rule.result.state, "inactive");
    assert!(changed_rule.nss_proven_directions.is_empty());

    let mut changed_lan = manager();
    changed_lan.rules.insert(identity.into(), rule);
    changed_lan.lan_device = "other-lan".into();
    changed_lan.inherit_nss_reload_state(&current);
    assert_eq!(changed_lan.result.state, "inactive");
    assert!(changed_lan.live.is_empty());
}

#[test]
fn queue_is_half_second_and_bounded() {
    assert_eq!(queue_bytes(8_000), MIN_QUEUE_BYTES);
    assert_eq!(queue_bytes(80_000_000), 5_000_000);
    assert_eq!(queue_bytes(u64::MAX), MAX_QUEUE_BYTES);
}

#[test]
fn ambiguous_identity_can_only_remove_or_relax_existing_control() {
    let previous = ControlRule {
        identity_key: "02:00:00:00:00:01@lan".into(),
        mac: "02:00:00:00:00:01".parse().unwrap(),
        upload_bps: 10_000_000,
        download_bps: 20_000_000,
        internet_disabled: true,
        class_minor: FIRST_CLASS_MINOR,
    };
    let request = |upload_bps, download_bps, internet_disabled| ClientControlRequest {
        identity_key: previous.identity_key.clone(),
        upload_bps,
        download_bps,
        internet_disabled,
    };
    assert!(control_update_is_not_more_restrictive(
        &previous,
        &request(0, 0, false)
    ));
    assert!(control_update_is_not_more_restrictive(
        &previous,
        &request(20_000_000, 20_000_000, false)
    ));
    assert!(!control_update_is_not_more_restrictive(
        &previous,
        &request(8_000_000, 20_000_000, false)
    ));
}

#[test]
fn identity_parser_rejects_command_text() {
    assert!(parse_identity_key("aa:bb:cc:dd:ee:01@lan;reboot").is_err());
    assert!(parse_identity_key("$(reboot)@lan").is_err());
    assert!(parse_identity_key("aa:bb:cc:dd:ee:01@lan").is_ok());
}

#[cfg(not(feature = "nss-platform"))]
#[test]
fn decimal_rate_parser_is_strict() {
    assert_eq!(parse_rate(Some("8000".into())).unwrap(), 8_000);
    assert!(parse_rate(Some("8mbit".into())).is_err());
    assert!(parse_rate(Some("8000;reboot".into())).is_err());
    assert!(parse_rate(Some("8001".into())).is_err());
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_build_accepts_only_its_u32_safe_rate_range() {
    assert_eq!(parse_rate(Some("0".into())).unwrap(), 0);
    assert_eq!(parse_rate(Some("8000".into())).unwrap(), 8_000);
    assert_eq!(
        parse_rate(Some(NSS_MAX_RATE_BPS.to_string())).unwrap(),
        NSS_MAX_RATE_BPS
    );
    assert!(parse_rate(Some((NSS_MAX_RATE_BPS + 8).to_string())).is_err());
}

#[cfg(feature = "nss-platform")]
#[test]
fn retired_conntrack_cleanup_requires_unique_live_ownership() {
    let unique = LiveClient {
        identity_key: "02:00:00:00:00:09@lan".into(),
        interface: Some("edge-test0".into()),
        ips: vec!["192.0.2.9".parse().unwrap(), "2001:db8::9".parse().unwrap()],
        ambiguous: false,
    };
    assert_eq!(deleted_rule_conntrack_ips(Some(&unique)), unique.ips);
    let ambiguous = LiveClient {
        ambiguous: true,
        ..unique
    };
    assert!(deleted_rule_conntrack_ips(Some(&ambiguous)).is_empty());
    assert!(deleted_rule_conntrack_ips(None).is_empty());
}

#[cfg(feature = "nss-platform")]
#[test]
fn ambiguous_retired_identity_waits_until_ownership_is_unique() {
    let identity = "02:00:00:00:00:09@lan";
    let mut manager = manager();
    let mut live = LiveClient {
        identity_key: identity.into(),
        interface: Some("edge-test0".into()),
        ips: vec!["192.0.2.9".parse().unwrap()],
        ambiguous: true,
    };
    manager.live.insert(identity.into(), live.clone());
    manager.pending_conntrack_identities.insert(identity.into());
    assert!(!manager.resolve_pending_conntrack_identities());
    assert!(manager.conntrack_cleanup_ips.is_empty());

    live.ambiguous = false;
    manager.live.insert(identity.into(), live);
    assert!(manager.resolve_pending_conntrack_identities());
    assert!(manager.pending_conntrack_identities.is_empty());
    assert_eq!(
        manager.conntrack_cleanup_ips,
        BTreeSet::from(["192.0.2.9".parse().unwrap()])
    );
}

#[test]
fn duplicate_ipv4_or_ipv6_ownership_fails_closed() {
    for ip in ["192.0.2.9", "2001:db8::9"] {
        let mut manager = manager();
        manager.observe_clients(&[
            client("02:00:00:00:00:01@lan", ip),
            client("02:00:00:00:00:02@lan", ip),
        ]);
        assert!(manager.live.values().all(|client| client.ambiguous));
    }
}

#[test]
fn unique_dual_stack_ownership_remains_usable() {
    let mut first = client("02:00:00:00:00:01@lan", "192.0.2.9");
    first.ips.push("2001:db8::9".into());
    let mut manager = manager();
    manager.observe_clients(&[first]);
    assert!(!manager.live.values().next().unwrap().ambiguous);
}

#[test]
fn unrelated_client_changes_do_not_dirty_the_active_control_plan() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let controlled = client(identity, "192.0.2.9");
    manager.observe_clients(std::slice::from_ref(&controlled));
    manager.dirty = false;

    manager.observe_clients(&[controlled, client("02:00:00:00:00:02@lan", "192.0.2.10")]);

    assert!(!manager.dirty);
}

#[test]
fn upload_rule_follows_the_clients_observed_interface() {
    let identity = "02:00:00:00:00:01@guest";
    let mut observed = client(identity, "192.0.2.9");
    observed.zone = "guest".into();
    set_client_interface(&mut observed, "br-guest");
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );

    manager.observe_clients(&[observed]);
    let plan = manager.plan();

    assert_eq!(plan.rules[0].interface, "br-guest");
    assert!(plan.control_devices.contains(&"br-lan".into()));
    assert!(plan.control_devices.contains(&"br-guest".into()));
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_control_ignores_untrusted_generic_interface_fields() {
    let identity = "02:00:00:00:00:01@guest";
    let mut observed = client(identity, "192.0.2.9");
    observed.interface = "proxy-edge".into();
    observed
        .rate_meta
        .as_mut()
        .and_then(|meta| meta.attachment.as_mut())
        .unwrap()
        .ifname = Some("trusted-edge".into());
    let mut manager = manager();
    manager.local_prefixes_ready = true;
    manager.last_local_prefix_refresh = Some(Instant::now());
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );

    manager.observe_clients(&[observed]);
    let plan = manager.plan();

    assert_eq!(plan.rules[0].interface, "trusted-edge");
    assert!(plan.control_devices.contains(&"trusted-edge".into()));
    assert!(!plan.control_devices.contains(&"proxy-edge".into()));
    assert!(!manager.local_prefixes_ready);
    assert!(manager.last_local_prefix_refresh.is_none());
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_control_rejects_unproven_wifi_attachment() {
    let identity = "02:00:00:00:00:01@guest";
    let mut observed = client(identity, "192.0.2.9");
    let attachment = observed
        .rate_meta
        .as_mut()
        .and_then(|meta| meta.attachment.as_mut())
        .unwrap();
    attachment.kind = crate::model::AttachmentKind::Wifi;
    attachment.ifname = Some("phy1-ap0".into());
    attachment.trust = crate::model::AttachmentTrust::Unknown;

    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );

    manager.observe_clients(&[observed]);

    assert!(manager.plan().rules.is_empty());
    assert!(!manager.control_devices.contains("phy1-ap0"));
}

#[test]
fn controlled_client_interface_change_dirties_the_plan() {
    let identity = "02:00:00:00:00:01@guest";
    let mut observed = client(identity, "192.0.2.9");
    set_client_interface(&mut observed, "br-guest");
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    manager.observe_clients(std::slice::from_ref(&observed));
    manager.dirty = false;

    set_client_interface(&mut observed, "br-iot");
    manager.observe_clients(&[observed]);

    assert!(manager.dirty);
    assert_eq!(manager.plan().rules[0].interface, "br-iot");
}

#[cfg(not(feature = "nss-platform"))]
#[test]
fn excluded_upload_interface_fails_closed() {
    let identity = "02:00:00:00:00:01@lan";
    let mut observed = client(identity, "192.0.2.9");
    set_client_interface(&mut observed, "dae0");
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );

    manager.observe_clients(&[observed]);

    assert!(manager.plan().rules.is_empty());
    assert_eq!(
        manager.summary(identity).reason.as_deref(),
        Some("identity_interface_unavailable")
    );
}

#[test]
fn early_bpf_mode_marks_control_topology_dirty() {
    let mut manager = manager();
    manager.observe_preempted_upload_devices(BTreeSet::from(["br-guest".into()]));
    assert!(manager.dirty);
    let identity = "02:00:00:00:00:01@lan";
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    manager.observe_clients(&[client(identity, "192.0.2.9")]);
    manager.live.get_mut(identity).unwrap().interface = Some("br-guest".into());
    assert!(manager.plan().rules[0].upload_preempted);
}

#[test]
fn supported_dae_bridge_slave_path_keeps_upload_rule_active() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    manager.observe_clients(&[client(identity, "192.0.2.9")]);
    manager.observe_preempted_upload_devices(BTreeSet::from(["br-lan".into()]));
    assert!(manager.plan().rules[0].upload_preempted);

    manager.observe_dae_upload_devices(BTreeSet::from(["eth1".into()]));
    let plan = manager.plan();
    assert_eq!(plan.dae_upload_devices, vec!["eth1"]);
    assert!(!plan.rules[0].upload_preempted);
    assert!(plan.rules[0].upload_before_proxy);
}

#[test]
fn active_ip_order_is_canonical_but_address_changes_dirty_the_plan() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let mut first = client(identity, "192.0.2.9");
    first.ips.push("2001:db8::9".into());
    manager.observe_clients(std::slice::from_ref(&first));
    manager.dirty = false;

    first.ips.reverse();
    manager.observe_clients(std::slice::from_ref(&first));
    assert!(!manager.dirty);

    first.ips.push("2001:db8::10".into());
    manager.observe_clients(&[first]);
    assert!(manager.dirty);
}

#[test]
fn unexpired_dhcp_lease_recovers_address_but_waits_for_the_observed_edge() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 0,
            download_bps: 10_000_000,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let leases = lease_addresses_from(
        "99 02:00:00:00:00:01 192.0.2.8 expired *\n\
             200 02:00:00:00:00:01 192.0.2.9 active *\n\
             200 02:00:00:00:00:02 192.0.2.10 other *\n",
        &manager.rules,
        100,
    );

    merge_control_lease_addresses(&mut manager.live, leases);

    assert!(manager.plan().rules.is_empty());
    assert_eq!(
        manager.live[identity].ips,
        vec!["192.0.2.9".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        manager.summary(identity).reason.as_deref(),
        Some("identity_interface_unavailable")
    );
}

#[test]
fn block_rule_waits_for_a_unique_ip_address() {
    let identity = "02:00:00:00:00:01@lan";
    let mut live = client(identity, "192.0.2.9");
    live.ips.clear();
    let mut manager = manager();
    manager.observe_clients(&[live]);
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 0,
            download_bps: 0,
            internet_disabled: true,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let plan = manager.plan();
    assert!(plan.rules.is_empty());
    assert_eq!(
        manager.summary(identity).reason.as_deref(),
        Some("identity_address_unavailable")
    );
}

#[cfg(not(feature = "nss-platform"))]
#[test]
fn mac_shaping_rule_remains_active_without_an_ip_address() {
    let identity = "02:00:00:00:00:01@lan";
    let mut live = client(identity, "192.0.2.9");
    live.ips.clear();
    let mut manager = manager();
    manager.observe_clients(&[live]);
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 8_000,
            download_bps: 8_000,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let plan = manager.plan();
    assert_eq!(plan.rules.len(), 1);
    assert_eq!(plan.rules[0].mac.to_string(), "02:00:00:00:00:01");
    assert!(plan.rules[0].ips.is_empty());
    assert_ne!(manager.summary(identity).state, "error");
}

#[test]
fn unsupported_shaping_exposes_reason_before_rule_configuration() {
    let mut manager = manager();
    manager.result.shaping_supported = false;
    manager.result.reason = Some("htb_qdisc_unavailable".into());
    let summary = manager.summary("02:00:00:00:00:01@lan");
    assert!(!summary.configured);
    assert!(!summary.shaping_supported);
    assert!(summary.blocking_supported);
    assert_eq!(summary.reason.as_deref(), Some("htb_qdisc_unavailable"));
}

#[test]
fn uci_section_names_are_stable_and_contain_no_identity_text() {
    let identity = "02:00:00:00:00:01@lan";
    let name = section_name(identity);
    assert_eq!(name, section_name(identity));
    assert!(name.starts_with("control_"));
    assert!(!name.contains("02:00"));
    assert_ne!(name, section_name("02:00:00:00:00:02@lan"));
}

#[test]
fn class_allocator_never_collides_with_default_fifo_handle() {
    let mut rules = BTreeMap::new();
    for index in 0..512u16 {
        let identity = format!("02:00:00:00:{:02x}:{:02x}@lan", index >> 8, index & 0xff);
        let minor = allocate_class_minor(&rules, &identity);
        assert_ne!(minor, DEFAULT_FIFO_HANDLE_MINOR);
        rules.insert(
            identity.clone(),
            ControlRule {
                identity_key: identity,
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 8_000,
                download_bps: 8_000,
                internet_disabled: false,
                class_minor: minor,
            },
        );
    }
}

#[test]
fn local_prefixes_are_normalized_and_overlaps_collapsed_for_nft_intervals() {
    let collapsed = collapse_prefixes(vec![
        ("192.0.2.9".parse().unwrap(), 24),
        ("192.0.2.1".parse().unwrap(), 32),
        ("127.0.0.1".parse().unwrap(), 32),
        ("127.0.0.0".parse().unwrap(), 8),
        ("2001:db8::9".parse().unwrap(), 64),
        ("2001:db8::1".parse().unwrap(), 128),
    ]);
    assert_eq!(
        collapsed,
        vec![
            ("127.0.0.0".parse().unwrap(), 8),
            ("192.0.2.0".parse().unwrap(), 24),
            ("2001:db8::".parse().unwrap(), 64),
        ]
    );
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_private_upstream_networks_remain_local() {
    let mut prefixes = Vec::new();
    append_nss_private_prefixes(&mut prefixes);
    assert!(prefixes.contains(&("10.0.0.0".parse().unwrap(), 8)));
    assert!(prefixes.contains(&("172.16.0.0".parse().unwrap(), 12)));
    assert!(prefixes.contains(&("192.168.0.0".parse().unwrap(), 16)));
    assert!(prefixes.contains(&("fc00::".parse().unwrap(), 7)));
}

#[test]
fn multicast_prefixes_normalize_to_lan_control_domains() {
    assert_eq!(
        normalize_prefix("224.0.0.1".parse().unwrap(), 4),
        Some(("224.0.0.0".parse().unwrap(), 4))
    );
    assert_eq!(
        normalize_prefix("ff02::1".parse().unwrap(), 8),
        Some(("ff00::".parse().unwrap(), 8))
    );
}

#[test]
fn connected_prefixes_are_added_only_for_controlled_lan_edges() {
    let interfaces = vec![
        json!({
            "ifname": "br-guest",
            "addr_info": [
                { "local": "192.0.2.1", "prefixlen": 24 },
                { "local": "2001:db8:1::1", "prefixlen": 64 }
            ]
        }),
        json!({
            "ifname": "wan",
            "addr_info": [{ "local": "198.51.100.2", "prefixlen": 24 }]
        }),
    ];
    let mut prefixes = Vec::new();
    append_interface_prefixes(
        &mut prefixes,
        &interfaces,
        &BTreeSet::from(["br-guest".into()]),
    );
    let collapsed = collapse_prefixes(prefixes);
    assert!(collapsed.contains(&("192.0.2.0".parse().unwrap(), 24)));
    assert!(collapsed.contains(&("2001:db8:1::".parse().unwrap(), 64)));
    assert!(collapsed.contains(&("198.51.100.2".parse().unwrap(), 32)));
    assert!(!collapsed.contains(&("198.51.100.0".parse().unwrap(), 24)));
}

#[test]
fn failed_dae_probe_retains_last_proven_topology() {
    let mut manager = manager();
    manager.observe_dae_topology(
        true,
        BTreeSet::from(["br-lan".into()]),
        BTreeSet::from(["lan2".into()]),
    );
    manager.observe_dae_topology_failure(true, BTreeSet::from(["br-guest".into()]));
    assert_eq!(
        manager.preempted_upload_devices,
        BTreeSet::from(["br-lan".into()])
    );
    assert_eq!(manager.dae_upload_devices, BTreeSet::from(["lan2".into()]));
}

#[test]
fn first_probe_failure_after_dae_starts_fails_closed() {
    let mut manager = manager();
    manager.observe_dae_topology(false, BTreeSet::new(), BTreeSet::new());
    manager
        .observe_dae_topology_failure(true, BTreeSet::from(["br-guest".into(), "br-lan".into()]));
    assert!(!manager.dae_topology_known);
    assert_eq!(
        manager.preempted_upload_devices,
        BTreeSet::from(["br-guest".into(), "br-lan".into()])
    );
    assert!(manager.dae_upload_devices.is_empty());
}

#[test]
fn platform_errors_never_publish_raw_command_or_address_text() {
    let raw = "tc_failed: device private0 at 192.0.2.99: qdisc_inspection_failed";
    assert_eq!(public_control_error(raw), "qdisc_inspection_failed");
    assert_eq!(
        public_control_error("secret unexpected stderr"),
        "control_apply_failed"
    );
    assert_eq!(
        public_control_error("cpu_path_qdisc_owned_by_external_service"),
        "cpu_path_qdisc_owned_by_external_service"
    );
}

#[test]
fn empty_conntrack_delete_is_success_but_real_errors_are_not() {
    assert!(conntrack_delete_succeeded(true, Some(0), b""));
    assert!(conntrack_delete_succeeded(
        false,
        Some(1),
        b"conntrack: 0 flow entries have been deleted"
    ));
    assert!(!conntrack_delete_succeeded(
        false,
        Some(1),
        b"operation not permitted"
    ));
}

#[test]
fn queue_overflow_requires_an_observed_drop_increment() {
    let previous = BTreeMap::from([("upload".into(), 3), ("download".into(), 7)]);
    assert!(!queue_drops_increased(
        &BTreeMap::new(),
        &BTreeMap::from([("upload".into(), 9)])
    ));
    assert!(!queue_drops_increased(
        &previous,
        &BTreeMap::from([("upload".into(), 3), ("download".into(), 6)])
    ));
    assert!(queue_drops_increased(
        &previous,
        &BTreeMap::from([("upload".into(), 4), ("download".into(), 7)])
    ));
}

#[test]
fn queue_overflow_is_not_reported_on_another_client() {
    let first = "02:00:00:00:00:01@lan";
    let second = "02:00:00:00:00:02@lan";
    let mut manager = manager();
    for (index, identity) in [first, second].into_iter().enumerate() {
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str(identity.split_once('@').unwrap().0).unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR + index as u16,
            },
        );
    }
    manager.result.state = "verified".into();
    manager.result.reason = None;
    manager.result.queue_overflow = true;
    manager
        .result
        .verification_failures
        .insert(first.into(), "queue_overflow".into());

    let failed = manager.summary(first);
    assert_eq!(failed.state, "error");
    assert_eq!(failed.reason.as_deref(), Some("queue_overflow"));
    assert!(failed.queue_overflow);

    let unaffected = manager.summary(second);
    assert_eq!(unaffected.state, "verified");
    assert_eq!(unaffected.reason, None);
    assert!(!unaffected.queue_overflow);
}

#[test]
fn failed_apply_state_is_not_hidden_by_counter_observation() {
    let mut manager = manager();
    manager.dirty = false;
    manager.result.state = "error".into();
    manager.result.reason = Some("queue_tree_verification_failed".into());

    manager.reconcile();

    assert_eq!(manager.result.state, "error");
    assert_eq!(
        manager.result.reason.as_deref(),
        Some("queue_tree_verification_failed")
    );
}

#[test]
fn block_only_rule_does_not_inherit_another_clients_pending_state() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 0,
            download_bps: 0,
            internet_disabled: true,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    manager.result.state = "pending_new_connections".into();
    manager.result.reason = Some("traffic_verification_pending".into());
    let summary = manager.summary(identity);
    assert_eq!(summary.state, "applied");
    assert_eq!(summary.reason, None);
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_path_evidence_retains_both_inputs_to_one_aggregate_executor() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );

    manager.observe_nss_paths(BTreeMap::from([(
        "02:00:00:00:00:02@lan".into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            proven_directions: NSS_CPU_UPLOAD,
            nss_directions: 0,
            cpu_directions: NSS_CPU_UPLOAD,
        },
    )]));
    assert!(!manager.dirty);
    assert!(manager.nss_proven_directions.is_empty());

    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            proven_directions: NSS_CPU_UPLOAD,
            nss_directions: 0,
            cpu_directions: NSS_CPU_UPLOAD,
        },
    )]));
    assert!(manager.dirty);
    assert!(manager.nss_proven_directions.is_empty());
    assert_eq!(
        manager.nss_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager.dirty = false;
    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            ..Default::default()
        },
    )]));
    assert!(!manager.dirty);
    assert_eq!(
        manager.nss_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager.observe_nss_paths(BTreeMap::new());
    assert!(!manager.dirty);
    assert_eq!(
        manager.nss_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            ..Default::default()
        },
    )]));
    assert!(!manager.dirty);
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            proven_directions: NSS_CPU_UPLOAD,
            nss_directions: NSS_CPU_UPLOAD,
            cpu_directions: 0,
        },
    )]));
    assert!(manager.dirty);
    assert_eq!(
        manager.nss_proven_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_active_nss_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager.dirty = false;
    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            proven_directions: NSS_CPU_UPLOAD,
            nss_directions: NSS_CPU_UPLOAD,
            cpu_directions: NSS_CPU_UPLOAD,
        },
    )]));
    assert!(!manager.dirty);
    assert_eq!(
        manager.nss_active_nss_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_active_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            ..Default::default()
        },
    )]));
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_proven_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
}

#[cfg(feature = "nss-platform")]
#[test]
fn nss_path_feedback_latches_until_counter_verification() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            proven_directions: NSS_CPU_UPLOAD,
            cpu_directions: NSS_CPU_UPLOAD,
            ..Default::default()
        },
    )]));
    manager.observe_nss_paths(BTreeMap::from([(
        identity.into(),
        NssPathObservation {
            valid_directions: NSS_CPU_UPLOAD,
            active_directions: NSS_CPU_UPLOAD,
            ..Default::default()
        },
    )]));
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
    assert_eq!(
        manager.nss_active_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager
        .result
        .cpu_verified_directions
        .insert(identity.into(), NSS_CPU_UPLOAD);
    manager.observe_nss_paths(BTreeMap::new());
    assert!(manager.nss_active_cpu_directions.is_empty());
    assert_eq!(
        manager.nss_path_ready_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );
}

#[cfg(feature = "nss-platform")]
#[test]
fn structural_rebuild_rearms_only_previously_proven_executors() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 100_000_000,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let directions = NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD;
    manager
        .nss_attachment_generations
        .insert(identity.into(), ("edge0".into(), 7));
    manager
        .nss_proven_directions
        .insert(identity.into(), NSS_CPU_DOWNLOAD);
    manager
        .nss_cpu_directions
        .insert(identity.into(), NSS_CPU_UPLOAD);
    manager
        .nss_path_ready_directions
        .insert(identity.into(), directions);

    manager.rearm_nss_executor_verification();
    assert_eq!(
        manager.nss_active_nss_directions.get(identity),
        Some(&NSS_CPU_DOWNLOAD)
    );
    assert_eq!(
        manager.nss_active_cpu_directions.get(identity),
        Some(&NSS_CPU_UPLOAD)
    );

    manager.observe_nss_attachment_generations(BTreeMap::from([(
        identity.into(),
        ("edge1".into(), 8),
    )]));
    manager.rearm_nss_executor_verification();
    assert!(manager.nss_active_nss_directions.is_empty());
    assert!(manager.nss_active_cpu_directions.is_empty());
}

#[cfg(feature = "nss-platform")]
#[test]
fn attachment_generation_change_invalidates_all_nss_path_proof() {
    let identity = "02:00:00:00:00:01@lan";
    let mut manager = manager();
    manager.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 100_000_000,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let directions = NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD;
    manager
        .nss_attachment_generations
        .insert(identity.into(), ("edge0".into(), 7));
    manager
        .nss_proven_directions
        .insert(identity.into(), directions);
    manager
        .nss_path_ready_directions
        .insert(identity.into(), directions);
    manager
        .nss_cpu_directions
        .insert(identity.into(), directions);
    manager
        .nss_active_nss_directions
        .insert(identity.into(), directions);
    manager
        .nss_active_cpu_directions
        .insert(identity.into(), directions);
    manager
        .result
        .verified_directions
        .insert(identity.into(), directions);
    manager
        .result
        .nss_verified_directions
        .insert(identity.into(), directions);
    manager
        .result
        .cpu_verified_directions
        .insert(identity.into(), directions);
    manager.dirty = false;

    manager.observe_nss_attachment_generations(BTreeMap::from([(
        identity.into(),
        ("edge0".into(), 8),
    )]));
    assert!(manager.dirty);
    assert!(manager.nss_proven_directions.is_empty());
    assert!(manager.nss_path_ready_directions.is_empty());
    assert!(manager.nss_cpu_directions.is_empty());
    assert!(manager.nss_active_nss_directions.is_empty());
    assert!(manager.nss_active_cpu_directions.is_empty());
    assert!(manager.result.verified_directions.is_empty());
    assert!(manager.result.nss_verified_directions.is_empty());
    assert!(manager.result.cpu_verified_directions.is_empty());
}

#[cfg(feature = "nss-platform")]
#[test]
fn reload_rebases_only_the_first_generation_on_the_same_attachment() {
    let identity = "02:00:00:00:00:01@lan";
    let mut current = manager();
    current.rules.insert(
        identity.into(),
        ControlRule {
            identity_key: identity.into(),
            mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
            upload_bps: 10_000_000,
            download_bps: 100_000_000,
            internet_disabled: false,
            class_minor: FIRST_CLASS_MINOR,
        },
    );
    let directions = NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD;
    current
        .nss_attachment_generations
        .insert(identity.into(), ("edge0".into(), 7));
    current
        .nss_proven_directions
        .insert(identity.into(), directions);
    current
        .nss_path_ready_directions
        .insert(identity.into(), directions);
    current
        .result
        .verified_directions
        .insert(identity.into(), directions);

    let mut candidate = manager();
    candidate.rules = current.rules.clone();
    candidate.inherit_nss_reload_state(&current);
    candidate.observe_nss_attachment_generations(BTreeMap::from([(
        identity.into(),
        ("edge0".into(), 8),
    )]));
    assert!(!candidate.nss_reload_attachment_rebase_pending);
    assert_eq!(
        candidate.nss_proven_directions.get(identity),
        Some(&directions)
    );
    assert_eq!(
        candidate.result.verified_directions.get(identity),
        Some(&directions)
    );

    candidate.observe_nss_attachment_generations(BTreeMap::from([(
        identity.into(),
        ("edge0".into(), 9),
    )]));
    assert!(candidate.nss_proven_directions.is_empty());
    assert!(candidate.result.verified_directions.is_empty());
}

#[cfg(feature = "nss-platform")]
#[test]
fn reload_attachment_rebase_rejects_a_changed_or_missing_edge() {
    let identity = "02:00:00:00:00:01@lan";
    for next in [
        BTreeMap::from([(identity.into(), ("edge1".into(), 8))]),
        BTreeMap::new(),
    ] {
        let mut current = manager();
        current.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 100_000_000,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        current
            .nss_attachment_generations
            .insert(identity.into(), ("edge0".into(), 7));
        current
            .nss_proven_directions
            .insert(identity.into(), NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD);
        current
            .result
            .verified_directions
            .insert(identity.into(), NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD);
        let mut candidate = manager();
        candidate.rules = current.rules.clone();
        candidate.inherit_nss_reload_state(&current);
        candidate.observe_nss_attachment_generations(next);
        assert!(candidate.nss_proven_directions.is_empty());
        assert!(candidate.result.verified_directions.is_empty());
    }
}
