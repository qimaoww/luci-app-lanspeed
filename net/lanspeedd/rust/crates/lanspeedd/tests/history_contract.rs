use lanspeedd::{
    config::{
        ConfigError, ConfigSource, ConfigValue, LegacyNameEligibility, RuntimeConfig,
        DEFAULT_MAX_CLIENTS, DEFAULT_REFRESH_INTERVAL_MS, MIN_REFRESH_INTERVAL_MS,
    },
    history::{
        coverage::{
            ByteTotals, CoverageQuality, CoverageRateAccumulator, CoverageRing, CoverageSample,
            COVERAGE_WINDOW,
        },
        overview::{
            ConnectionTotals, ConnectionTotalsOverride, OverviewClient, OverviewConfig,
            OverviewRing, OVERVIEW_WINDOW,
        },
    },
    rate::{
        ClientCounters, RateBook, RateWarning, RATE_BASELINE_RETENTION_MS, RATE_WINDOW_COUNT,
        STALE_CLIENT_MS,
    },
};
use serde_json::Value;
use std::fs;

struct RefreshSource(String);

impl ConfigSource for RefreshSource {
    fn get(&mut self, path: &str) -> Result<Option<ConfigValue>, ConfigError> {
        Ok((path == "lanspeed.main.refresh_interval_ms")
            .then(|| ConfigValue::String(self.0.clone())))
    }
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/../../../../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn counters(identity_key: &str, tx_bytes: u64, rx_bytes: u64, last_seen_ms: u64) -> ClientCounters {
    ClientCounters {
        identity_key: identity_key.to_owned(),
        tx_bytes,
        rx_bytes,
        last_seen_ms,
    }
}

#[test]
fn upload_fixture_uses_the_exact_integer_delta_formula_and_three_slots() {
    let fixture = fixture("lanspeed-upload-rate.json");
    let key = format!(
        "{}@{}",
        fixture["client"]["mac"].as_str().unwrap(),
        fixture["client"]["zone"].as_str().unwrap()
    );
    let mut rates = RateBook::new(8, STALE_CLIENT_MS);
    let mut observed = Vec::new();

    for sample in fixture["samples"].as_array().unwrap() {
        let now_ms = sample["t_ms"].as_u64().unwrap();
        let update = rates.update(
            now_ms,
            [counters(&key, sample["bytes"].as_u64().unwrap(), 0, now_ms)],
        );
        observed.push(update.clients[0].tx_bps);
    }

    assert_eq!(RATE_WINDOW_COUNT, 3);
    assert_eq!(rates.window_len(&key), Some(3));
    assert!(observed.contains(&10_000_000));
    assert_eq!(
        &observed[1..],
        &[10_000_000, 10_000_000, 10_000_000, 0, 80_000, 0]
    );

    let fractional = RateBook::rate_from_delta(2, 1, 3);
    assert_eq!(
        fractional.bps, 2_666,
        "legacy C uses integer floor, not rounding"
    );
    assert!(fractional.warning.is_none());
}

#[test]
fn counter_and_time_rollbacks_are_zero_without_poisoning_healthy_rates() {
    let fixture = fixture("lanspeed-counter-anomaly.json");
    let key = fixture["client"]["identity_key"].as_str().unwrap();
    let healthy = fixture["unaffected_clients"][0]["identity_key"]
        .as_str()
        .unwrap();
    let mut rates = RateBook::new(8, STALE_CLIENT_MS);

    rates.update(
        0,
        [counters(key, 4_000_000, 0, 0), counters(healthy, 0, 0, 0)],
    );
    let rollback = rates.update(
        1_000,
        [
            counters(key, 3_000_000, 250_000, 1_000),
            counters(healthy, 125_000, 250_000, 1_000),
        ],
    );
    let anomalous = rollback.client(key).unwrap();
    let unaffected = rollback.client(healthy).unwrap();
    assert_eq!(anomalous.tx_bps, 0);
    assert_eq!(anomalous.rx_bps, 2_000_000);
    assert_eq!(anomalous.warnings, [RateWarning::CounterAnomaly]);
    assert_eq!(
        (unaffected.tx_bps, unaffected.rx_bps),
        (1_000_000, 2_000_000)
    );
    assert!(unaffected.warnings.is_empty());
    assert_eq!(rollback.warnings, [RateWarning::CounterAnomaly]);
    assert_eq!(
        anomalous.to_json()["warnings"],
        serde_json::json!(["counter_anomaly"])
    );

    let mut reset_baseline = RateBook::new(1, STALE_CLIENT_MS);
    reset_baseline.update(0, [counters(key, 4_000_000, 0, 0)]);
    reset_baseline.update(1_000, [counters(key, 3_000_000, 0, 1_000)]);
    let recovered = reset_baseline.update(2_000, [counters(key, 4_250_000, 0, 2_000)]);
    assert_eq!(recovered.clients[0].tx_bps, 10_000_000);

    let time_rollback = rates.update(
        900,
        [
            counters(key, 3_500_000, 300_000, 900),
            counters(healthy, 250_000, 500_000, 900),
        ],
    );
    assert!(time_rollback
        .clients
        .iter()
        .all(|client| client.tx_bps == 0 && client.rx_bps == 0));
    assert_eq!(time_rollback.warnings, [RateWarning::TimeRollback]);
    assert!(time_rollback
        .clients
        .iter()
        .all(|client| client.warnings == [RateWarning::TimeRollback]));

    let same_time = rates.update(900, [counters(key, 3_600_000, 310_000, 900)]);
    assert_eq!(
        (same_time.clients[0].tx_bps, same_time.clients[0].rx_bps),
        (0, 0)
    );
    assert!(same_time.warnings.is_empty());
}

#[test]
fn client_local_time_rollback_warns_resets_baseline_and_isolates_other_clients() {
    let mut rates = RateBook::new(2, STALE_CLIENT_MS);
    rates.update(
        1_000,
        [
            counters("a@lan", 1_000, 0, 1_000),
            counters("b@lan", 1_000, 0, 1_000),
        ],
    );

    rates.update(900, [counters("b@lan", 1_000, 0, 1_000)]);
    let returned = rates.update(
        950,
        [
            counters("a@lan", 1_100, 0, 950),
            counters("b@lan", 1_100, 0, 950),
        ],
    );

    let a = returned.client("a@lan").unwrap();
    let b = returned.client("b@lan").unwrap();
    assert_eq!(a.tx_bps, 0);
    assert_eq!(a.warnings, [RateWarning::TimeRollback]);
    assert_eq!(b.tx_bps, 16_000);
    assert!(b.warnings.is_empty());
    assert_eq!(returned.warnings, [RateWarning::TimeRollback]);

    let recovered = rates.update(1_050, [counters("a@lan", 1_200, 0, 1_050)]);
    assert_eq!(recovered.clients[0].tx_bps, 8_000);
    assert!(recovered.clients[0].warnings.is_empty());
    assert!(recovered.warnings.is_empty());
}

#[test]
fn rate_arithmetic_and_json_conversion_saturate_instead_of_wrapping() {
    let delta = RateBook::rate_from_delta(u64::MAX, 0, 1);
    assert_eq!(delta.bps, u64::MAX);
    assert!(delta.warning.is_none());

    let mut rates = RateBook::new(1, STALE_CLIENT_MS);
    rates.update(0, [counters("max@lan", 0, 0, 0)]);
    let update = rates.update(1, [counters("max@lan", u64::MAX, u64::MAX, 1)]);
    let json = update.clients[0].to_json();
    assert_eq!(json["tx_bps"], i64::MAX);
    assert_eq!(json["rx_bps"], i64::MAX);
    assert_eq!(json["tx_bytes"], i64::MAX);
    assert_eq!(json["rx_bytes"], i64::MAX);
}

#[test]
fn refresh_interval_fixture_is_clamped_by_the_production_configuration() {
    let fixture = fixture("lanspeed-refresh-interval.json");
    let mut source = RefreshSource(fixture["configured_ms"].as_u64().unwrap().to_string());
    let config = RuntimeConfig::load(&mut source, &LegacyNameEligibility).unwrap();

    assert_eq!(DEFAULT_REFRESH_INTERVAL_MS, fixture["default_ms"]);
    assert_eq!(MIN_REFRESH_INTERVAL_MS, fixture["minimum_ms"]);
    assert_eq!(config.refresh_interval_ms, fixture["effective_ms"]);
    assert!(config.refresh_interval_clamped);
}

#[test]
fn a_hostile_client_limit_does_not_trigger_an_eager_allocation() {
    let mut rates = RateBook::new(usize::MAX, STALE_CLIENT_MS);
    let samples = (0..=DEFAULT_MAX_CLIENTS).map(|index| {
        counters(
            &format!(
                "02:00:00:{:02x}:{:02x}:{:02x}@lan",
                index >> 16,
                index >> 8,
                index
            ),
            0,
            0,
            0,
        )
    });
    let update = rates.update(0, samples);
    assert_eq!(rates.identity_keys().count(), DEFAULT_MAX_CLIENTS);
    assert_eq!(update.rejected_clients.len(), 1);
}

#[test]
fn stale_limit_and_map_failure_semantics_match_the_resource_fixture() {
    let fixture = fixture("lanspeed-resource-limits.json");
    assert_eq!(fixture["stale_client_ms"], STALE_CLIENT_MS);
    let now_ms = fixture["now_ms"].as_u64().unwrap();
    let max_clients = fixture["max_clients"].as_u64().unwrap() as usize;
    let mut rates = RateBook::new(max_clients, STALE_CLIENT_MS);
    let samples = fixture["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|client| {
            counters(
                client["identity_key"].as_str().unwrap(),
                0,
                0,
                client["last_seen"].as_u64().unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let update = rates.update(now_ms, samples);
    assert_eq!(update.clients.len(), max_clients);
    assert_eq!(update.rejected_clients, ["02:00:00:00:00:04@lan"]);
    assert_eq!(update.warnings, [RateWarning::ClientLimitExceeded]);
    assert!(!rates.contains("02:00:00:00:00:02@lan"));
    assert!(rates.contains("02:00:00:00:00:01@lan"));
    assert!(rates.contains("02:00:00:00:00:03@lan"));

    let before = rates.identity_keys().collect::<Vec<_>>();
    let failed = rates.map_read_failed();
    assert_eq!(failed.warnings, [RateWarning::MapReadFailed]);
    assert_eq!(rates.identity_keys().collect::<Vec<_>>(), before);

    let mut boundary = RateBook::new(2, STALE_CLIENT_MS);
    let boundary_update = boundary.update(
        now_ms,
        [
            counters("boundary@lan", 0, 0, now_ms - STALE_CLIENT_MS),
            counters("expired@lan", 0, 0, now_ms - STALE_CLIENT_MS - 1),
        ],
    );
    assert_eq!(boundary_update.clients.len(), 1);
    assert!(boundary.contains("boundary@lan"));
    assert!(
        boundary.contains("expired@lan"),
        "first-seen stale counters should seed a hidden return baseline"
    );
}

#[test]
fn inactive_clients_keep_a_hidden_baseline_for_an_accurate_first_return_sample() {
    let mut rates = RateBook::new(2, STALE_CLIENT_MS);
    rates.update(1_000, [counters("returning@lan", 1_000, 2_000, 1_000)]);

    let hidden = rates.update(20_000, [counters("returning@lan", 1_000, 2_000, 1_000)]);
    assert!(hidden.clients.is_empty());
    assert!(rates.contains("returning@lan"));

    let returned = rates.update(21_000, [counters("returning@lan", 2_000, 4_000, 21_000)]);
    assert_eq!(returned.clients.len(), 1);
    assert_eq!(returned.clients[0].tx_bps, 8_000);
    assert_eq!(returned.clients[0].rx_bps, 16_000);

    rates.update(
        21_000 + RATE_BASELINE_RETENTION_MS + 1,
        std::iter::empty::<ClientCounters>(),
    );
    assert!(!rates.contains("returning@lan"));
}

#[test]
fn stale_baselines_are_evicted_before_rejecting_a_new_active_client() {
    let mut rates = RateBook::new(1, STALE_CLIENT_MS);
    rates.update(1_000, [counters("old@lan", 1_000, 0, 1_000)]);
    rates.update(20_000, [counters("old@lan", 1_000, 0, 1_000)]);

    let replacement = rates.update(21_000, [counters("new@lan", 1_000, 0, 21_000)]);
    assert_eq!(replacement.clients.len(), 1);
    assert!(replacement.rejected_clients.is_empty());
    assert!(!rates.contains("old@lan"));
    assert!(rates.contains("new@lan"));
}

#[test]
fn coverage_rate_accumulator_is_monotonic_precise_and_pauses_gaps() {
    let mut accumulator = CoverageRateAccumulator::default();
    assert_eq!(
        accumulator.update(1_000, 8_004, 16_004),
        ByteTotals::new(0, 0)
    );
    assert_eq!(
        accumulator.update(2_000, 8_004, 16_004),
        ByteTotals::new(1_000, 2_000)
    );
    assert_eq!(
        accumulator.update(3_000, 8_004, 16_004),
        ByteTotals::new(2_001, 4_001),
        "fractional byte remainders must carry across samples"
    );

    accumulator.pause();
    assert_eq!(
        accumulator.update(30_000, 8_000_000, 8_000_000),
        ByteTotals::new(2_001, 4_001),
        "unsupported gaps must not integrate a stale rate"
    );
    assert_eq!(accumulator.totals(), ByteTotals::new(2_001, 4_001));
}

#[test]
fn coverage_ring_is_fixed_and_distinguishes_idle_low_traffic_and_ok_quality() {
    let mut ring = CoverageRing::new();
    assert_eq!(ring.capacity(), COVERAGE_WINDOW);
    ring.push(CoverageSample::valid(
        0,
        ByteTotals::new(0, 0),
        ByteTotals::new(0, 0),
    ));
    ring.push(CoverageSample::valid(
        2_999,
        ByteTotals::new(1_000_000, 1_000_000),
        ByteTotals::new(900_000, 800_000),
    ));
    assert_eq!(ring.report(true).quality, CoverageQuality::Warmup);

    ring.push(CoverageSample::valid(
        3_000,
        ByteTotals::new(200_000, 200_000),
        ByteTotals::new(100_000, 100_000),
    ));
    assert_eq!(ring.report(true).quality, CoverageQuality::LowTraffic);

    let mut idle = CoverageRing::new();
    idle.push(CoverageSample::valid(
        0,
        ByteTotals::new(100, 200),
        ByteTotals::new(50, 100),
    ));
    idle.push(CoverageSample::valid(
        3_000,
        ByteTotals::new(100, 200),
        ByteTotals::new(50, 100),
    ));
    assert_eq!(idle.report(true).quality, CoverageQuality::Idle);

    let mut ring = CoverageRing::new();
    ring.push(CoverageSample::valid(
        0,
        ByteTotals::new(0, 0),
        ByteTotals::new(0, 0),
    ));
    ring.push(CoverageSample::valid(
        3_000,
        ByteTotals::new(1_000_000, 2_000_000),
        ByteTotals::new(1_500_000, 500_000),
    ));
    let ok = ring.report(true);
    assert_eq!(ok.quality, CoverageQuality::Ok);
    assert_eq!(ok.tx_pct, Some(50));
    assert_eq!(ok.rx_pct, Some(75));

    for index in 1..=COVERAGE_WINDOW {
        ring.push(CoverageSample::valid(
            3_000 + index as u64,
            ByteTotals::new(index as u64, index as u64),
            ByteTotals::new(index as u64, index as u64),
        ));
    }
    assert_eq!(ring.len(), COVERAGE_WINDOW);
}

#[test]
fn coverage_unsupported_shape_and_counter_reset_match_legacy_json() {
    let mut unsupported = CoverageRing::new();
    unsupported.push(CoverageSample::invalid(1_000));
    assert_eq!(
        unsupported.report(false).to_json(),
        serde_json::json!({"quality": "unsupported", "samples": 1})
    );
    assert_eq!(unsupported.len(), 1);

    let mut ring = CoverageRing::new();
    ring.push(CoverageSample::valid(
        1_000,
        ByteTotals::new(10_000, 20_000),
        ByteTotals::new(8_000, 18_000),
    ));
    ring.push(CoverageSample::valid(
        5_000,
        ByteTotals::new(9_999, 30_000),
        ByteTotals::new(9_000, 19_000),
    ));
    let reset = ring.report(true);
    assert_eq!(reset.quality, CoverageQuality::CounterReset);
    assert_eq!(reset.samples, 0);
    assert_eq!(reset.window_ms, 4_000);
    assert_eq!(ring.len(), 0);
    assert_eq!(reset.to_json()["denom_rx_bytes"], 0);
}

fn overview_client(
    tx_bps: u64,
    rx_bps: u64,
    sample_ms: u64,
    last_seen_ms: u64,
    connections: ConnectionTotals,
) -> OverviewClient {
    OverviewClient {
        tx_bps,
        rx_bps,
        sample_ms,
        last_seen_ms,
        connections,
    }
}

#[test]
fn overview_active_rules_and_connection_overrides_are_exact() {
    let config = OverviewConfig {
        window_samples: 240,
        active_client_window_ms: 10_000,
        active_client_min_bps: 100,
    };
    let mut ring = OverviewRing::new();
    let clients = [
        overview_client(60, 40, 20_000, 10_000, ConnectionTotals::new(1, 2, 1, 1)),
        overview_client(100, 0, 20_000, 9_999, ConnectionTotals::new(3, 4, 2, 2)),
        overview_client(
            u64::MAX,
            1,
            20_000,
            20_000,
            ConnectionTotals::new(5, 6, 3, 3),
        ),
        overview_client(100, 0, 0, 0, ConnectionTotals::new(7, 8, 4, 4)),
        overview_client(100, 0, 20_000, 20_001, ConnectionTotals::new(9, 10, 5, 5)),
    ];
    ring.push(
        20_000,
        &clients,
        ConnectionTotalsOverride {
            tcp_conns: Some(u64::MAX),
            udp_dns_conns: Some(77),
            ..ConnectionTotalsOverride::default()
        },
        &config,
    );

    let sample = ring.latest().unwrap();
    assert_eq!(sample.active_clients, 2);
    assert_eq!(sample.tx_bps, u64::MAX);
    assert_eq!(sample.rx_bps, 41);
    assert_eq!(sample.tcp_conns, u32::MAX);
    assert_eq!(sample.udp_conns, 30);
    assert_eq!(sample.udp_dns_conns, 77);
    assert_eq!(sample.udp_other_conns, 15);
    let json = ring.to_json(&config);
    assert_eq!(json["samples"][0]["tx_bps"], i64::MAX);
    assert_eq!(json["samples"][0]["tcp_conns"], u32::MAX);
}

#[test]
fn on_demand_connections_replace_the_latest_overview_population() {
    let config = OverviewConfig {
        window_samples: 240,
        active_client_window_ms: 10_000,
        active_client_min_bps: 1,
    };
    let mut ring = OverviewRing::new();
    ring.push(
        10_000,
        &[overview_client(
            1_000,
            2_000,
            10_000,
            10_000,
            ConnectionTotals::new(9, 8, 7, 6),
        )],
        ConnectionTotalsOverride::default(),
        &config,
    );
    let before = *ring.latest().unwrap();

    assert!(ring.replace_latest_connections_and_client_count(ConnectionTotals::new(2, 3, 1, 2), 7,));

    let after = *ring.latest().unwrap();
    assert_eq!(ring.len(), 1);
    assert_eq!(after.sample_ms, before.sample_ms);
    assert_eq!(after.tx_bps, before.tx_bps);
    assert_eq!(after.rx_bps, before.rx_bps);
    assert_eq!(after.client_count, 7);
    assert_eq!(after.active_clients, before.active_clients);
    assert_eq!(after.tcp_conns, 2);
    assert_eq!(after.udp_conns, 3);
    assert_eq!(after.udp_dns_conns, 1);
    assert_eq!(after.udp_other_conns, 2);
}

#[test]
fn overview_ring_caps_at_240_and_serializes_recent_window_oldest_first() {
    let fixture = fixture("lanspeed-overview.json");
    let config = OverviewConfig {
        window_samples: 3,
        active_client_window_ms: fixture["active_client_window_ms"].as_u64().unwrap(),
        active_client_min_bps: fixture["active_client_min_bps"].as_u64().unwrap(),
    };
    let mut ring = OverviewRing::new();
    assert_eq!(ring.capacity(), OVERVIEW_WINDOW);
    for sample_ms in 0..(OVERVIEW_WINDOW as u64 + 5) {
        ring.push(sample_ms, &[], ConnectionTotalsOverride::default(), &config);
    }
    assert_eq!(ring.len(), OVERVIEW_WINDOW);

    let json = ring.to_json(&config);
    let samples = json["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 3);
    assert_eq!(samples[0]["sample_ms"], 242);
    assert_eq!(samples[2]["sample_ms"], 244);
    assert_eq!(json["max_samples"], 240);
    assert_eq!(json["overview_window_samples"], 3);
    assert_eq!(json["active_client_window_ms"], 10_000);
    assert_eq!(json["active_client_min_bps"], 1);
    assert_eq!(json["sample_source"], "clients_refresh_daemon_ring");
    assert_eq!(
        json["conn_semantics"],
        "conntrack_current_tcp_established_assured_udp_assured_dns_split"
    );
}
