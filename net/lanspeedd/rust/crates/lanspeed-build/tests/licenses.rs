use std::{fs, path::Path};

#[test]
fn workspace_is_apache_2_and_bpf_declares_gpl_kfunc_compatibility() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(workspace.contains("license = \"Apache-2.0\""));

    for member in [
        "lanspeed-common",
        "lanspeed-ebpf",
        "lanspeed-openwrt-sys",
        "lanspeedd",
        "lanspeed-build",
    ] {
        let manifest =
            fs::read_to_string(root.join("crates").join(member).join("Cargo.toml")).unwrap();
        assert!(
            manifest.contains("license.workspace = true"),
            "{member} must inherit the workspace license"
        );
    }

    let ebpf = fs::read_to_string(root.join("crates/lanspeed-ebpf/src/main.rs")).unwrap();
    assert!(ebpf.contains("static LICENSE: [u8; 4] = *b\"GPL\\0\";"));
}
