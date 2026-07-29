use lanspeedd::config::{InterfaceEligibility, SysfsInterfaceEligibility, ARPHRD_ETHER};
use std::fs;

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
