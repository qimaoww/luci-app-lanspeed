use lanspeedd::config::{
    ConfigError, ConfigSource, ConfigValue, ConnectionCollectorMode, InterfaceEligibility,
    LegacyNameEligibility, RateCollectorMode, RuntimeConfig, DEFAULT_ACTIVE_CLIENT_MIN_BPS,
    DEFAULT_ACTIVE_CLIENT_WINDOW_MS, DEFAULT_MAX_CLIENTS, DEFAULT_OVERVIEW_WINDOW_SAMPLES,
    DEFAULT_REFRESH_INTERVAL_MS, MAX_INTERFACE_NAMES, MAX_INTERFACE_NAME_LEN,
    MAX_OVERVIEW_WINDOW_SAMPLES, MIN_ACTIVE_CLIENT_WINDOW_MS, MIN_OVERVIEW_WINDOW_SAMPLES,
    MIN_REFRESH_INTERVAL_MS,
};
use std::collections::HashMap;

#[derive(Default)]
struct MemorySource {
    values: HashMap<String, ConfigValue>,
    failure: Option<String>,
}

impl MemorySource {
    fn with(mut self, option: &str, value: impl Into<String>) -> Self {
        self.values.insert(
            format!("lanspeed.main.{option}"),
            ConfigValue::String(value.into()),
        );
        self
    }

    fn with_list(mut self, option: &str, values: &[&str]) -> Self {
        self.values.insert(
            format!("lanspeed.main.{option}"),
            ConfigValue::List(values.iter().map(|value| (*value).to_owned()).collect()),
        );
        self
    }

    fn failing(message: &str) -> Self {
        Self {
            failure: Some(message.to_owned()),
            ..Self::default()
        }
    }
}

impl ConfigSource for MemorySource {
    fn get(&mut self, path: &str) -> Result<Option<ConfigValue>, ConfigError> {
        if let Some(message) = &self.failure {
            return Err(ConfigError::Source(message.clone()));
        }
        Ok(self.values.get(path).cloned())
    }
}

struct RejectNamed(&'static str);

impl InterfaceEligibility for RejectNamed {
    fn is_collect_eligible(&self, name: &str) -> bool {
        name != self.0
    }
}

fn load(source: MemorySource) -> RuntimeConfig {
    let mut source = source;
    RuntimeConfig::load(&mut source, &LegacyNameEligibility).unwrap()
}

#[cfg(feature = "openwrt")]
#[test]
fn real_uci_wrapper_is_a_configuration_source() {
    fn assert_source<T: ConfigSource>() {}
    assert_source::<lanspeed_openwrt_sys::UciContext>();
}

#[test]
fn defaults_and_limits_match_the_legacy_c_contract() {
    assert_eq!(DEFAULT_REFRESH_INTERVAL_MS, 1_000);
    assert_eq!(MIN_REFRESH_INTERVAL_MS, 500);
    assert_eq!(DEFAULT_MAX_CLIENTS, 2_048);
    assert_eq!(DEFAULT_ACTIVE_CLIENT_WINDOW_MS, 10_000);
    assert_eq!(MIN_ACTIVE_CLIENT_WINDOW_MS, 1_000);
    assert_eq!(DEFAULT_ACTIVE_CLIENT_MIN_BPS, 1);
    assert_eq!(DEFAULT_OVERVIEW_WINDOW_SAMPLES, 240);
    assert_eq!(MIN_OVERVIEW_WINDOW_SAMPLES, 2);
    assert_eq!(MAX_OVERVIEW_WINDOW_SAMPLES, 240);
    assert_eq!(MAX_INTERFACE_NAMES, 16);
    assert_eq!(MAX_INTERFACE_NAME_LEN, 32);

    let config = RuntimeConfig::default();
    assert_eq!(config.refresh_interval_ms, 1_000);
    assert_eq!(config.max_clients, 2_048);
    assert_eq!(config.active_client_window_ms, 10_000);
    assert_eq!(config.active_client_min_bps, 1);
    assert_eq!(config.overview_window_samples, 240);
    assert!(!config.enable_bpf);
    assert!(config.enable_conntrack_fallback);
    assert_eq!(config.rate_collector_mode, RateCollectorMode::Auto);
    assert_eq!(config.conn_collector_mode, ConnectionCollectorMode::Auto);
    assert!(!config.refresh_interval_clamped);
    assert!(!config.active_client_window_clamped);
    assert!(!config.active_client_min_bps_clamped);
    assert!(!config.overview_window_samples_clamped);
    assert!(config.ifnames.is_empty());
    assert!(config.interface_include.is_empty());
    assert!(config.interface_exclude.is_empty());
    assert!(config.observe_ifnames.is_empty());
    assert!(!config.rejected_nssifb_collect);
}

#[test]
fn rate_collector_accepts_every_legacy_string_and_canonicalizes_the_alias() {
    let cases = [
        ("auto", RateCollectorMode::Auto, "auto"),
        ("bpf", RateCollectorMode::Bpf, "bpf"),
        (
            "nss_ecm_direct",
            RateCollectorMode::NssEcmDirect,
            "nss_ecm_direct",
        ),
        (
            "nss_conntrack_sync",
            RateCollectorMode::NssConntrackSync,
            "nss_conntrack_sync",
        ),
        (
            "conntrack_ecm_sync",
            RateCollectorMode::NssConntrackSync,
            "nss_conntrack_sync",
        ),
    ];

    for (input, expected, canonical) in cases {
        assert_eq!(RateCollectorMode::parse(input), Some(expected), "{input}");
        assert_eq!(expected.as_str(), canonical, "{input}");
    }
    assert_eq!(RateCollectorMode::parse("conntrack_netlink"), None);
    assert_eq!(RateCollectorMode::parse("BPF"), None);
}

#[test]
fn connection_collector_accepts_every_legacy_string() {
    let cases = [
        ("auto", ConnectionCollectorMode::Auto, "auto"),
        (
            "conntrack_netlink",
            ConnectionCollectorMode::ConntrackNetlink,
            "conntrack_netlink",
        ),
        (
            "conntrack_procfs",
            ConnectionCollectorMode::ConntrackProcfs,
            "conntrack_procfs",
        ),
    ];

    for (input, expected, canonical) in cases {
        assert_eq!(ConnectionCollectorMode::parse(input), Some(expected));
        assert_eq!(expected.as_str(), canonical);
    }
    assert_eq!(ConnectionCollectorMode::parse("bpf"), None);
    assert_eq!(ConnectionCollectorMode::parse("CONNTRACK_NETLINK"), None);
}

#[test]
fn legacy_collector_mode_maps_one_dimension_and_split_options_override_it() {
    let bpf = load(MemorySource::default().with("collector_mode", "bpf"));
    assert_eq!(bpf.rate_collector_mode, RateCollectorMode::Bpf);
    assert_eq!(bpf.conn_collector_mode, ConnectionCollectorMode::Auto);

    let netlink = load(MemorySource::default().with("collector_mode", "conntrack_netlink"));
    assert_eq!(netlink.rate_collector_mode, RateCollectorMode::Auto);
    assert_eq!(
        netlink.conn_collector_mode,
        ConnectionCollectorMode::ConntrackNetlink
    );

    let procfs = load(MemorySource::default().with("collector_mode", "conntrack_procfs"));
    assert_eq!(procfs.rate_collector_mode, RateCollectorMode::Auto);
    assert_eq!(
        procfs.conn_collector_mode,
        ConnectionCollectorMode::ConntrackProcfs
    );

    let reset = load(
        MemorySource::default()
            .with("collector_mode", "conntrack_procfs")
            .with("rate_collector_mode", "bpf")
            .with("conn_collector_mode", "auto"),
    );
    assert_eq!(reset.rate_collector_mode, RateCollectorMode::Bpf);
    assert_eq!(reset.conn_collector_mode, ConnectionCollectorMode::Auto);

    let invalid_split_preserves_legacy = load(
        MemorySource::default()
            .with("collector_mode", "conntrack_netlink")
            .with("rate_collector_mode", "conntrack_procfs")
            .with("conn_collector_mode", "bpf"),
    );
    assert_eq!(
        invalid_split_preserves_legacy.rate_collector_mode,
        RateCollectorMode::Auto
    );
    assert_eq!(
        invalid_split_preserves_legacy.conn_collector_mode,
        ConnectionCollectorMode::ConntrackNetlink
    );
}

#[test]
fn scalar_options_preserve_legacy_boolean_and_zero_semantics() {
    let config = load(
        MemorySource::default()
            .with("refresh_interval_ms", "2500")
            .with("max_clients", "0")
            .with("active_client_window_ms", "30000")
            .with("active_client_min_bps", "128")
            .with("overview_window_samples", "42")
            .with("enable_bpf", "true")
            .with("enable_conntrack_fallback", "0"),
    );

    assert_eq!(config.refresh_interval_ms, 2_500);
    assert_eq!(config.max_clients, 0);
    assert_eq!(config.active_client_window_ms, 30_000);
    assert_eq!(config.active_client_min_bps, 128);
    assert_eq!(config.overview_window_samples, 42);
    assert!(config.enable_bpf);
    assert!(!config.enable_conntrack_fallback);

    let strict_boolean = load(
        MemorySource::default()
            .with("enable_bpf", "TRUE")
            .with("enable_conntrack_fallback", "yes"),
    );
    assert!(!strict_boolean.enable_bpf);
    assert!(!strict_boolean.enable_conntrack_fallback);

    let c_style_numbers = load(
        MemorySource::default()
            .with("refresh_interval_ms", " 250ms")
            .with("active_client_window_ms", "1500ms")
            .with("max_clients", "not-a-number"),
    );
    assert_eq!(c_style_numbers.refresh_interval_ms, 500);
    assert!(c_style_numbers.refresh_interval_clamped);
    assert_eq!(c_style_numbers.active_client_window_ms, 1_500);
    assert_eq!(c_style_numbers.max_clients, 0);

    let negative_signed_values = load(
        MemorySource::default()
            .with("refresh_interval_ms", "-1")
            .with("max_clients", "-1"),
    );
    assert_eq!(
        negative_signed_values.refresh_interval_ms,
        DEFAULT_REFRESH_INTERVAL_MS
    );
    assert!(!negative_signed_values.refresh_interval_clamped);
    assert_eq!(negative_signed_values.max_clients, DEFAULT_MAX_CLIENTS);

    for overflow in ["18446744073709551616", "-18446744073709551616"] {
        let overflowed = load(
            MemorySource::default()
                .with("active_client_window_ms", overflow)
                .with("active_client_min_bps", overflow),
        );
        assert_eq!(overflowed.active_client_window_ms, u64::MAX, "{overflow}");
        assert_eq!(overflowed.active_client_min_bps, u64::MAX, "{overflow}");
    }
}

#[test]
fn numeric_parsing_skips_only_c_locale_ascii_whitespace() {
    let ascii =
        load(MemorySource::default().with("refresh_interval_ms", " \t\n\r\u{000b}\u{000c}500"));
    assert_eq!(ascii.refresh_interval_ms, 500);

    for unicode_space in ['\u{00a0}', '\u{3000}'] {
        let value = format!("{unicode_space}500");
        let config = load(MemorySource::default().with("refresh_interval_ms", value));
        assert_eq!(config.refresh_interval_ms, DEFAULT_REFRESH_INTERVAL_MS);
        assert!(!config.refresh_interval_clamped);
    }
}

#[test]
fn every_clamped_value_sets_its_machine_readable_flag() {
    let low = load(
        MemorySource::default()
            .with("refresh_interval_ms", "1")
            .with("active_client_window_ms", "999")
            .with("active_client_min_bps", "0")
            .with("overview_window_samples", "1"),
    );
    assert_eq!(low.refresh_interval_ms, 500);
    assert_eq!(low.active_client_window_ms, 1_000);
    assert_eq!(low.active_client_min_bps, 1);
    assert_eq!(low.overview_window_samples, 2);
    assert!(low.refresh_interval_clamped);
    assert!(low.active_client_window_clamped);
    assert!(low.active_client_min_bps_clamped);
    assert!(low.overview_window_samples_clamped);

    let high = load(MemorySource::default().with("overview_window_samples", "241"));
    assert_eq!(high.overview_window_samples, 240);
    assert!(high.overview_window_samples_clamped);

    let zeros_keep_c_defaults = load(
        MemorySource::default()
            .with("refresh_interval_ms", "0")
            .with("active_client_window_ms", "0")
            .with("overview_window_samples", "0"),
    );
    assert_eq!(zeros_keep_c_defaults.refresh_interval_ms, 1_000);
    assert_eq!(zeros_keep_c_defaults.active_client_window_ms, 10_000);
    assert_eq!(zeros_keep_c_defaults.overview_window_samples, 240);
    assert!(!zeros_keep_c_defaults.refresh_interval_clamped);
    assert!(!zeros_keep_c_defaults.active_client_window_clamped);
    assert!(!zeros_keep_c_defaults.overview_window_samples_clamped);
}

#[test]
fn list_options_are_preserved_deduplicated_and_bounded() {
    let many = (0..40).map(|i| format!("lan{i}")).collect::<Vec<_>>();
    let mut source = MemorySource::default()
        .with_list("ifname", &["br-lan", "eth1", "br-lan"])
        .with("interface_include", "wlan0, wlan1 lan2")
        .with_list("interface_exclude", &["wan", "pppoe-wan"])
        .with_list("observe", &["nssifb", "eth0", "eth0"]);
    source.values.insert(
        "lanspeed.main.interface_include".into(),
        ConfigValue::List(many),
    );
    let config = load(source);

    assert_eq!(config.ifnames, ["br-lan", "eth1"]);
    assert_eq!(config.interface_include.len(), MAX_INTERFACE_NAMES - 2);
    assert_eq!(config.interface_include.first().unwrap(), "lan0");
    assert_eq!(config.interface_include.last().unwrap(), "lan13");
    assert_eq!(config.interface_exclude, ["wan", "pppoe-wan"]);
    assert_eq!(config.observe_ifnames, ["nssifb", "eth0"]);

    let single_string = load(
        MemorySource::default()
            .with("ifname", "br-lan eth1")
            .with_list("observe", &["br-lan eth1", "eth0"]),
    );
    assert_eq!(single_string.ifnames, ["br-lan eth1"]);
    assert_eq!(single_string.observe_ifnames, ["eth0"]);

    let accepted = "a".repeat(MAX_INTERFACE_NAME_LEN - 1);
    let rejected = "b".repeat(MAX_INTERFACE_NAME_LEN);
    let mut boundary = MemorySource::default();
    boundary.values.insert(
        "lanspeed.main.ifname".into(),
        ConfigValue::List(vec![accepted.clone(), rejected]),
    );
    assert_eq!(load(boundary).ifnames, [accepted]);
}

#[test]
fn nssifb_is_rejected_from_both_collect_lists_but_remains_observe_only() {
    let config = load(
        MemorySource::default()
            .with_list("ifname", &["nssifb", "br-lan"])
            .with_list("interface_include", &["eth1", "nssifb"])
            .with_list("observe", &["nssifb"]),
    );

    assert_eq!(config.ifnames, ["br-lan"]);
    assert_eq!(config.interface_include, ["eth1"]);
    assert_eq!(config.observe_ifnames, ["nssifb"]);
    assert!(config.rejected_nssifb_collect);
}

#[test]
fn proxy_and_tunnel_prefixes_are_ignored_for_collect_and_observe() {
    let ignored = [
        "dae0",
        "daed-edge",
        "miireg0",
        "tun0",
        "erspan0",
        "gretap0",
        "gre0",
        "ip6gre0",
        "ip6tnl0",
        "sit0",
        "bonding_masters",
    ];
    for name in ignored {
        assert!(!LegacyNameEligibility.is_collect_eligible(name), "{name}");
    }

    let config = load(
        MemorySource::default()
            .with_list("ifname", &["br-lan", "gretap0", "dae0"])
            .with_list(
                "observe",
                &["wan", "nssifb", "tun0", "erspan0", "bonding_masters"],
            ),
    );
    assert_eq!(config.ifnames, ["br-lan"]);
    assert_eq!(config.observe_ifnames, ["wan", "nssifb"]);
}

#[test]
fn observe_accepts_uplinks_but_rejects_unsafe_and_auto_ignored_names() {
    let config = load(MemorySource::default().with_list(
        "observe",
        &[
            "wan",
            "wg0",
            "pppoe-wan",
            "nssifb",
            ".",
            "..",
            "nested/name",
            "bad\0name",
            "dae0",
            "tun0",
        ],
    ));

    assert_eq!(
        config.observe_ifnames,
        ["wan", "wg0", "pppoe-wan", "nssifb"]
    );
}

#[test]
fn auto_ignored_collect_names_do_not_consume_the_sixteen_interface_limit() {
    let mut names = [
        "dae0",
        "miireg0",
        "tun0",
        "erspan0",
        "gretap0",
        "gre0",
        "ip6gre0",
        "ip6tnl0",
        "sit0",
        "bonding_masters",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    names.extend((0..MAX_INTERFACE_NAMES).map(|index| format!("lan{index}")));
    let mut source = MemorySource::default();
    source
        .values
        .insert("lanspeed.main.ifname".into(), ConfigValue::List(names));

    let config = load(source);
    assert_eq!(config.ifnames.len(), MAX_INTERFACE_NAMES);
    assert_eq!(config.ifnames.first().map(String::as_str), Some("lan0"));
    assert_eq!(config.ifnames.last().map(String::as_str), Some("lan15"));
}

#[test]
fn runtime_interface_views_defend_against_direct_or_stale_config_values() {
    let mut config = RuntimeConfig::default();
    config.ifnames = vec![
        "br-lan".into(),
        "dae0".into(),
        "tun0".into(),
        "nssifb".into(),
        "pppoe-wan".into(),
        "nested/name".into(),
        "bad\0name".into(),
    ];
    config.interface_include = vec!["lan1".into(), "br-lan".into(), "..".into()];
    config.observe_ifnames = vec![
        "wan".into(),
        "wg0".into(),
        "nssifb".into(),
        "dae0".into(),
        "nested/name".into(),
        "br-lan".into(),
    ];

    assert_eq!(config.runtime_collect_ifnames(), ["br-lan", "lan1"]);
    assert_eq!(config.runtime_observe_ifnames(), ["wan", "wg0", "nssifb"]);
}

#[test]
fn sysdevice_candidates_hide_auto_ignored_and_unsafe_names() {
    use lanspeedd::config::is_sysdevice_candidate;

    assert!(is_sysdevice_candidate("br-lan"));
    assert!(is_sysdevice_candidate("wan"));
    for name in [
        "lo",
        "teql0",
        "dae0",
        "tun0",
        ".",
        "..",
        "nested/name",
        "bad\0name",
    ] {
        assert!(!is_sysdevice_candidate(name), "{name}");
    }
}

#[test]
fn nssifb_rejection_is_recorded_even_after_the_collect_limit_is_full() {
    let mut values = (0..MAX_INTERFACE_NAMES + 1)
        .map(|index| format!("lan{index}"))
        .collect::<Vec<_>>();
    values.push("nssifb".into());
    let mut source = MemorySource::default();
    source
        .values
        .insert("lanspeed.main.ifname".into(), ConfigValue::List(values));

    let config = load(source);
    assert_eq!(config.ifnames.len(), MAX_INTERFACE_NAMES);
    assert!(config.rejected_nssifb_collect);
}

#[test]
fn ineligible_collect_names_do_not_consume_capacity() {
    let mut names = (0..MAX_INTERFACE_NAMES)
        .map(|index| format!("wan{index}"))
        .collect::<Vec<_>>();
    names.push("br-lan".into());
    let mut source = MemorySource::default();
    source
        .values
        .insert("lanspeed.main.ifname".into(), ConfigValue::List(names));

    let config = RuntimeConfig::load(&mut source, &LegacyNameEligibility).unwrap();
    assert_eq!(config.ifnames, ["br-lan"]);

    let mut injected = MemorySource::default().with_list("ifname", &["nonether0", "br-lan"]);
    let config = RuntimeConfig::load(&mut injected, &RejectNamed("nonether0")).unwrap();
    assert_eq!(config.ifnames, ["br-lan"]);
}

#[cfg(feature = "openwrt")]
#[test]
fn missing_uci_package_loads_runtime_defaults() {
    let directory =
        std::env::temp_dir().join(format!("lanspeed-missing-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let mut source = lanspeed_openwrt_sys::UciContext::with_confdir(&directory).unwrap();

    let loaded = RuntimeConfig::load(&mut source, &LegacyNameEligibility).unwrap();
    assert_eq!(loaded, RuntimeConfig::default());

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn atomic_reload_replaces_only_a_fully_valid_candidate() {
    let mut config = RuntimeConfig::default();
    let mut valid = MemorySource::default()
        .with("refresh_interval_ms", "2000")
        .with_list("ifname", &["lo", "br-lan"]);
    let policy = RejectNamed("lo");
    config.reload(&mut valid, &policy).unwrap();
    assert_eq!(config.refresh_interval_ms, 2_000);
    assert_eq!(config.ifnames, ["br-lan"]);

    let before = config.clone();
    let mut failed = MemorySource::failing("uci context unavailable");
    assert_eq!(
        config.reload(&mut failed, &policy),
        Err(ConfigError::Source("uci context unavailable".into()))
    );
    assert_eq!(config, before);

    let mut wrong_type = MemorySource::default().with_list("refresh_interval_ms", &["500"]);
    assert!(matches!(
        config.reload(&mut wrong_type, &policy),
        Err(ConfigError::WrongType { option, .. }) if option == "refresh_interval_ms"
    ));
    assert_eq!(config, before);
}
