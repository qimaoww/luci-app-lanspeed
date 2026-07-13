use lanspeedd::{
    config::{InterfaceEligibility, SysfsInterfaceEligibility, ARPHRD_ETHER},
    interfaces::lan_coverage_totals,
    model::{Interface, InterfaceRole, InterfaceStatus},
};
use std::fs;

fn interface(
    name: &str,
    role: InterfaceRole,
    status: InterfaceStatus,
    rx_bytes: u64,
    tx_bytes: u64,
) -> Interface {
    Interface {
        name: name.into(),
        role,
        status,
        rx_bytes: Some(rx_bytes),
        tx_bytes: Some(tx_bytes),
        rx_bps: Some(0),
        tx_bps: Some(0),
        delta_ms: Some(1_000),
        sample_ms: Some(1_000),
        source: None,
        coverage: None,
        evidence: None,
    }
}

#[test]
fn coverage_denominator_uses_unique_available_lan_interfaces_only() {
    let interfaces = vec![
        interface(
            "br-lan",
            InterfaceRole::Lan,
            InterfaceStatus::Available,
            100,
            200,
        ),
        interface(
            "br-lan",
            InterfaceRole::Lan,
            InterfaceStatus::Available,
            100,
            200,
        ),
        interface(
            "pppoe-wan",
            InterfaceRole::Observe,
            InterfaceStatus::Available,
            10_000,
            20_000,
        ),
        interface(
            "ifb0",
            InterfaceRole::Observe,
            InterfaceStatus::Available,
            30_000,
            40_000,
        ),
        interface(
            "eth2",
            InterfaceRole::Lan,
            InterfaceStatus::Missing,
            50_000,
            60_000,
        ),
        interface(
            "eth3",
            InterfaceRole::Wan,
            InterfaceStatus::Available,
            70_000,
            80_000,
        ),
    ];

    let totals = lan_coverage_totals(&interfaces);
    assert_eq!(totals.rx_bytes, 100);
    assert_eq!(totals.tx_bytes, 200);
}

#[test]
fn coverage_denominator_saturates_and_treats_missing_counters_as_zero() {
    let mut first = interface(
        "lan0",
        InterfaceRole::Lan,
        InterfaceStatus::Available,
        u64::MAX,
        7,
    );
    first.tx_bytes = None;
    let second = interface(
        "lan1",
        InterfaceRole::Lan,
        InterfaceStatus::Available,
        1,
        u64::MAX,
    );

    let totals = lan_coverage_totals(&[first, second]);
    assert_eq!(totals.rx_bytes, u64::MAX);
    assert_eq!(totals.tx_bytes, u64::MAX);
}

#[test]
fn sysfs_eligibility_requires_ethernet_link_type_and_legacy_safe_name() {
    let root =
        std::env::temp_dir().join(format!("lanspeed-interface-types-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for (name, link_type) in [
        ("br-lan", ARPHRD_ETHER.to_string()),
        ("gre0", "778".into()),
        ("sit0", "776".into()),
        ("raw0", "519".into()),
        ("tun0", ARPHRD_ETHER.to_string()),
        ("broken0", "not-a-number".into()),
    ] {
        let directory = root.join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("type"), format!("{link_type}\n")).unwrap();
    }
    let escape_name = format!("lanspeed-interface-escape-{}", std::process::id());
    let escape = root.parent().unwrap().join(&escape_name);
    fs::create_dir_all(&escape).unwrap();
    fs::write(escape.join("type"), format!("{ARPHRD_ETHER}\n")).unwrap();

    let eligibility = SysfsInterfaceEligibility::new(&root);
    assert!(eligibility.is_collect_eligible("br-lan"));
    for name in [
        "gre0",
        "sit0",
        "raw0",
        "tun0",
        "broken0",
        "missing0",
        ".",
        "..",
        "../br-lan",
        "nested/name",
        "bad\0name",
    ] {
        assert!(!eligibility.is_collect_eligible(name), "{name}");
    }
    let traversal = format!("../{escape_name}");
    assert!(!eligibility.is_collect_eligible(&traversal));

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(escape).unwrap();
}
