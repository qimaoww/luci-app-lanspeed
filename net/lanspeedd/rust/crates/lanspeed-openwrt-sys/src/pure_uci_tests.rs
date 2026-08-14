#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::CString,
        os::unix::ffi::OsStrExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn isolated_context(directory: &Path) -> UciContext {
        let mut context = UciContext::with_confdir(directory).unwrap();
        context.conf2dir = directory.join("conf2");
        context.savedir = directory.join("saved");
        context
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lanspeed-pure-uci-{label}-{}-{suffix}",
            std::process::id()
        ))
    }

    fn apply_delta_records(package: &mut UciPackage, input: &[u8]) {
        let mut offset = 0;
        while offset < input.len() {
            let (argument, next_offset) = parse_delta_argument(input, offset);
            if let Some(delta) = argument.and_then(|word| parse_delta(&package.name, &word)) {
                apply_delta(package, delta);
            }
            offset = next_offset;
        }
    }

    fn option_value<'a>(
        package: &'a UciPackage,
        section_name: &str,
        option_name: &str,
    ) -> Option<&'a UciValue> {
        package
            .sections
            .iter()
            .find(|section| section.name == section_name)
            .and_then(|section| {
                section
                    .options
                    .iter()
                    .find(|option| option.name == option_name)
            })
            .map(|option| &option.value)
    }

    #[test]
    fn reads_named_sections_strings_lists_comments_and_escapes() {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("lanspeed-pure-uci-{}-{suffix}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("lanspeed"), "# comment\nconfig main 'main'\n option mode 'auto'\n list ifname 'br-lan'\n list ifname \"eth\\ 1\"\n").unwrap();
        let mut context = isolated_context(&directory);
        assert_eq!(
            context.lookup("lanspeed.main.mode").unwrap(),
            Some(UciValue::String("auto".into()))
        );
        assert_eq!(
            context.lookup("lanspeed.main.ifname").unwrap(),
            Some(UciValue::List(vec!["br-lan".into(), "eth 1".into()]))
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn repeated_named_section_of_the_same_type_merges_like_strict_libuci() {
        let package = parse_package(
            "lanspeed",
            b"config main 'main'\n option first '1'\n\
              config main 'other'\n option untouched 'yes'\n\
              config main 'main'\n option second '2'\n",
        )
        .unwrap();

        assert_eq!(package.sections.len(), 2);
        assert_eq!(package.sections[0].name, "main");
        assert_eq!(package.sections[1].name, "other");
        assert_eq!(
            package.sections[0].options,
            vec![
                UciOption {
                    name: "first".into(),
                    value: UciValue::String("1".into()),
                },
                UciOption {
                    name: "second".into(),
                    value: UciValue::String("2".into()),
                },
            ]
        );
        assert_eq!(
            package.sections[1].options,
            vec![UciOption {
                name: "untouched".into(),
                value: UciValue::String("yes".into()),
            }]
        );
        assert!(parse_package(
            "lanspeed",
            b"config main 'main'\nconfig incompatible 'main'\n"
        )
        .is_err());
    }

    #[test]
    fn anonymous_section_ids_match_libuci_djb_hash_names() {
        assert_eq!(anonymous_section_name("defaults", 1), "cfg01e63d");
        assert_eq!(anonymous_section_name("zone", 2), "cfg02dc81");
        assert_eq!(anonymous_section_name("zone", 3), "cfg03dc81");
    }

    #[test]
    fn command_abbreviations_and_empty_arguments_match_libuci() {
        let package = parse_package(
            "lanspeed",
            b"p lanspeed\n\
              c kind ''\n\
              o keep 'first'\n\
              o keep\n\
              o keep ''\n\
              l blanks\n\
              l blanks ''\n",
        )
        .unwrap();

        assert_eq!(package.sections.len(), 1);
        assert_eq!(package.sections[0].name, "cfg01894b");
        assert!(package.sections[0].anonymous);
        assert_eq!(
            option_value(&package, "cfg01894b", "keep"),
            Some(&UciValue::String("first".into()))
        );
        assert_eq!(
            option_value(&package, "cfg01894b", "blanks"),
            Some(&UciValue::List(vec![String::new(), String::new()]))
        );
    }

    #[test]
    fn bounded_reader_rejects_fifos_and_files_over_the_limit() {
        let directory = temporary_directory("bounded-read");
        fs::create_dir_all(&directory).unwrap();

        let fifo = directory.join("fifo");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        assert!(matches!(read_bounded_regular_file(&fifo), Ok(None)));

        let mut context = isolated_context(&directory);
        fs::rename(&fifo, directory.join("lanspeed")).unwrap();
        assert!(matches!(
            context.load_package("lanspeed"),
            Err(Error::Platform {
                operation: "uci_load",
                code: UCI_ERR_NOTFOUND
            })
        ));

        let oversized = directory.join("oversized");
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&oversized)
            .unwrap();
        file.set_len((MAX_UCI_FILE_LEN as u64) + 1).unwrap();
        assert!(matches!(
            read_bounded_regular_file(&oversized),
            Err(BoundedReadError::TooLarge)
        ));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn multiline_delta_and_strict_single_argument_rules_match_libuci() {
        let mut package =
            parse_package("lanspeed", b"config main 'main'\n option original 'base'\n").unwrap();
        apply_delta_records(
            &mut package,
            b"lanspeed.main.multiline='line1\nline2'\n\
              lanspeed.main.continued=\"left\\\nright\"\n\
              lanspeed.main.trailing='ignored' \n\
              lanspeed.main.extra='ignored' extra\n\
              lanspeed.main.semicolon='ignored';\n\
              lanspeed.main.comment='accepted'#comment\n",
        );

        assert_eq!(
            option_value(&package, "main", "multiline"),
            Some(&UciValue::String("line1\nline2".into()))
        );
        assert_eq!(
            option_value(&package, "main", "continued"),
            Some(&UciValue::String("leftright".into()))
        );
        assert_eq!(option_value(&package, "main", "trailing"), None);
        assert_eq!(option_value(&package, "main", "extra"), None);
        assert_eq!(option_value(&package, "main", "semicolon"), None);
        assert_eq!(
            option_value(&package, "main", "comment"),
            Some(&UciValue::String("accepted".into()))
        );
    }

    #[test]
    fn delta_rename_allows_duplicates_and_makes_sections_named() {
        let mut package = parse_package(
            "lanspeed",
            b"config kind\n option first '1'\n\
              config kind 'taken'\n option second '2'\n",
        )
        .unwrap();
        assert!(package.sections[0].anonymous);

        apply_delta_records(&mut package, b"@lanspeed.cfg01894b='taken'\n");

        assert_eq!(
            package
                .sections
                .iter()
                .map(|section| section.name.as_str())
                .collect::<Vec<_>>(),
            vec!["taken", "taken"]
        );
        assert!(!package.sections[0].anonymous);
    }

    #[test]
    fn delta_list_index_removal_matches_sscanf_prefix_semantics() {
        let mut package = parse_package(
            "lanspeed",
            b"config main 'main'\n\
              list no_value 'a'\n list no_value 'b'\n\
              list empty_value 'a'\n list empty_value 'b'\n\
              list prefix 'a'\n list prefix 'b'\n list prefix 'c'\n\
              list negative 'a'\n list negative 'b'\n\
              list invalid 'a'\n list invalid 'b'\n\
              list out_of_range 'a'\n list out_of_range 'b'\n",
        )
        .unwrap();
        apply_delta_records(
            &mut package,
            b"-lanspeed.main.no_value\n\
              -lanspeed.main.empty_value=''\n\
              -lanspeed.main.prefix='1junk'\n\
              -lanspeed.main.negative='-1'\n\
              -lanspeed.main.invalid='junk'\n\
              -lanspeed.main.out_of_range='99'\n",
        );

        assert_eq!(option_value(&package, "main", "no_value"), None);
        assert_eq!(option_value(&package, "main", "empty_value"), None);
        assert_eq!(
            option_value(&package, "main", "prefix"),
            Some(&UciValue::List(vec!["a".into(), "c".into()]))
        );
        for name in ["negative", "invalid", "out_of_range"] {
            assert_eq!(
                option_value(&package, "main", name),
                Some(&UciValue::List(vec!["a".into(), "b".into()]))
            );
        }
    }

    #[test]
    fn missing_package_uses_the_libuci_not_found_contract() {
        let directory =
            std::env::temp_dir().join(format!("lanspeed-pure-uci-missing-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let mut context = isolated_context(&directory);
        assert!(matches!(
            context.load_package("missing"),
            Err(Error::Platform {
                operation: "uci_load",
                code: 3
            })
        ));
        assert_eq!(context.lookup("missing.main.value").unwrap(), None);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn non_utf8_values_match_the_former_libuci_lossy_string_contract() {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "lanspeed-pure-uci-non-utf8-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("lanspeed"),
            b"config main 'main'\n option label 'legacy-\xff-value'\n",
        )
        .unwrap();

        let mut context = isolated_context(&directory);
        assert_eq!(
            context.lookup("lanspeed.main.label").unwrap(),
            Some(UciValue::String("legacy-\u{fffd}-value".into()))
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conf2_override_and_saved_delta_match_libuci_read_semantics() {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "lanspeed-pure-uci-overlay-{}-{suffix}",
            std::process::id()
        ));
        let conf2dir = directory.join("conf2");
        let savedir = directory.join("saved");
        fs::create_dir_all(&conf2dir).unwrap();
        fs::create_dir_all(&savedir).unwrap();
        fs::write(
            directory.join("lanspeed"),
            "config main-v1 'main'\n option label 'base'\n",
        )
        .unwrap();
        fs::write(
            conf2dir.join("lanspeed"),
            "config main-v1 'main'\n option label 'override'\n option remove_me 'yes'\n list ifname 'br-lan'\n",
        )
        .unwrap();
        fs::write(
            savedir.join("lanspeed"),
            "malformed delta line\n\
             lanspeed.main.mode='delta value'\n\
             |lanspeed.main.ifname='eth9'\n\
             ~lanspeed.main.ifname='br-lan'\n\
             -lanspeed.main.remove_me\n\
             +lanspeed.extra='probe-kind'\n\
             lanspeed.extra.enabled='1'\n\
             @lanspeed.extra='renamed'\n\
             ^lanspeed.renamed='0'\n",
        )
        .unwrap();

        let mut context = isolated_context(&directory);
        assert_eq!(
            context.lookup("lanspeed.main.label").unwrap(),
            Some(UciValue::String("override".into()))
        );
        assert_eq!(
            context.lookup("lanspeed.main.mode").unwrap(),
            Some(UciValue::String("delta value".into()))
        );
        assert_eq!(
            context.lookup("lanspeed.main.ifname").unwrap(),
            Some(UciValue::List(vec!["eth9".into()]))
        );
        assert_eq!(context.lookup("lanspeed.main.remove_me").unwrap(), None);

        let package = context.load_package("lanspeed").unwrap();
        assert_eq!(package.sections[0].name, "renamed");
        assert_eq!(package.sections[0].kind, "probe-kind");
        assert!(!package.sections[0].anonymous);
        assert!(package.sections[0].options.contains(&UciOption {
            name: "enabled".into(),
            value: UciValue::String("1".into()),
        }));
        assert_eq!(package.sections[1].name, "main");
        assert_eq!(package.sections[1].kind, "main-v1");

        fs::remove_dir_all(directory).unwrap();
    }
}
