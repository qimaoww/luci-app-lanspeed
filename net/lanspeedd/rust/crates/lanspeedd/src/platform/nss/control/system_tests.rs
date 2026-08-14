#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_control_command_is_killed_at_its_deadline() {
        let child = Command::new("sleep")
            .arg("5")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        assert_eq!(
            wait_output_with_timeout(child, "sleep", Duration::from_millis(30)).unwrap_err(),
            "nss_control_command_timeout"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn script_stdin_is_closed_before_waiting_for_the_child() {
        let start = Instant::now();
        run_script("/bin/sh", &["-c", "cat >/dev/null"], "payload\n").unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn command_output_is_drained_while_the_child_is_running() {
        let child = Command::new("dd")
            .args(["if=/dev/zero", "bs=1048576", "count=2"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let output = wait_output_with_timeout(child, "dd", Duration::from_secs(2)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), COMMAND_OUTPUT_CAP);
    }

    #[test]
    fn one_observation_reuses_identical_read_output_but_not_mutations() {
        let path = std::env::temp_dir().join(format!(
            "lanspeedd-nss-observation-cache-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let script = format!("printf x >> '{}'; printf payload", path.display());
        with_observation_cache(|| {
            assert_eq!(output("/bin/sh", &["-c", &script]).unwrap().stdout, b"payload");
            assert_eq!(output("/bin/sh", &["-c", &script]).unwrap().stdout, b"payload");
        });
        assert_eq!(fs::read(&path).unwrap(), b"x");
        run("/bin/sh", &["-c", &script]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"xx");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn interface_names_reject_shell_and_paths() {
        assert!(valid_interface_name("uplink0"));
        assert!(!valid_interface_name("uplink;reboot"));
        assert!(!valid_interface_name("../uplink"));
    }

    #[test]
    fn sysfs_ifindex_must_be_a_positive_integer() {
        assert!(valid_ifindex("1\n"));
        assert!(valid_ifindex("4294967295"));
        assert!(!valid_ifindex("0"));
        assert!(!valid_ifindex("bonding_masters"));
        assert!(!valid_ifindex("1 2"));
    }

    #[test]
    fn qdisc_parser_accepts_libwrt_nss_text_without_json_support() {
        let values = parse_qdiscs(
            "qdisc nsshtb 7d00: root refcnt 2 r2q 10 accel_mode 0\n\
             qdisc nssbfifo 8001: parent 7d00:123 limit 625000b accel_mode 0\n",
        )
        .unwrap();
        assert_eq!(values[0].kind, "nsshtb");
        assert!(values[0].root);
        assert_eq!(values[1].parent.as_deref(), Some("7d00:123"));
    }

    #[test]
    fn replaceable_root_policy_rejects_non_default_handles() {
        let default = QdiscInfo {
            kind: "fq_codel".into(),
            handle: "0:".into(),
            parent: None,
            root: true,
        };
        let external = QdiscInfo {
            handle: "1234:".into(),
            ..default.clone()
        };
        assert!(system_default_root(&default));
        assert!(!system_default_root(&external));
    }

    #[test]
    fn tc_filter_parser_collapses_qca_u32_and_matchall_metadata_rows() {
        let values = tc_filter_values(
            br#"[
                {"protocol":"ip","pref":100,"kind":"u32","chain":32288},
                {"protocol":"ip","pref":100,"kind":"u32","chain":32288,
                 "options":{"fh":"800:","ht_divisor":1}},
                {"protocol":"ip","pref":100,"kind":"u32","chain":32288,
                 "options":{"fh":"800::800","order":2048,"actions":[{"kind":"gact"}]}},
                {"protocol":"all","pref":65534,"kind":"matchall","chain":32288},
                {"protocol":"all","pref":65534,"kind":"matchall","chain":32288,
                 "options":{"handle":32288,"actions":[{"kind":"gact"}]}},
                {"protocol":"ip","pref":200,"kind":"flower","chain":32288}
            ]"#,
            "bad_filters",
        )
        .unwrap();
        assert_eq!(values.len(), 3);
        assert_eq!(values[0]["options"]["order"], 2048);
        assert_eq!(values[1]["options"]["handle"], 32288);
        assert_eq!(values[2]["kind"], "flower");
    }

    #[test]
    fn pref_scoped_qca_output_recovers_only_the_command_selector() {
        let values = tc_filter_values_at_pref(
            br#"[
                {"protocol":"all","kind":"matchall","chain":0},
                {"protocol":"all","kind":"matchall","chain":0,
                 "options":{"handle":32288,"actions":[{"kind":"gact"}]}}
            ]"#,
            53_280,
            "bad_filters",
        )
        .unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["pref"], 53_280);
        assert_eq!(values[0]["options"]["handle"], 32_288);
    }

    #[test]
    fn lossless_tc_parser_preserves_duplicate_u32_match_keys() {
        let values = tc_u32_match_sets(
            br#"[
                {"protocol":"ip","pref":10000,"kind":"u32"},
                {"protocol":"ip","pref":10000,"kind":"u32",
                 "options":{"fh":"800:","ht_divisor":1}},
                {"protocol":"ip","pref":10000,"kind":"u32",
                 "options":{"fh":"800::800","order":2048,
                    "match":{"value":"2000000","mask":"ffffffff","off":-8},
                    "match":{"value":"90000","mask":"ffff0000","off":-4}}}
            ]"#,
            "bad_filters",
        )
        .unwrap();
        assert_eq!(
            values,
            vec![TcU32MatchSet {
                protocol: "ip".into(),
                pref: 10_000,
                matches: vec![
                    TcU32Match {
                        value: "2000000".into(),
                        mask: "ffffffff".into(),
                        offset: -8,
                    },
                    TcU32Match {
                        value: "90000".into(),
                        mask: "ffff0000".into(),
                        offset: -4,
                    },
                ],
            }]
        );
    }
}
