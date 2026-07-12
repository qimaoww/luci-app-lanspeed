use std::{fs, path::PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn custom_aya_and_vendor_resolution_do_not_depend_on_the_current_directory() {
    let workspace = workspace_root();
    let manifest = fs::read_to_string(workspace.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("aya = { path = \"vendor/aya\", version = \"=0.14.0\" }"));
    assert!(manifest.contains("exclude = [\"vendor/aya\"]"));

    let lock = fs::read_to_string(workspace.join("Cargo.lock")).unwrap();
    let aya = lock
        .split("[[package]]")
        .find(|package| package.contains("name = \"aya\""))
        .unwrap();
    assert!(
        !aya.contains("source = "),
        "custom Aya must be path-resolved"
    );

    let repository = workspace.join("../../..").canonicalize().unwrap();
    let root_config = fs::read_to_string(repository.join(".cargo/config.toml")).unwrap();
    assert!(root_config.contains("directory = \"net/lanspeedd/rust/vendor\""));
    assert!(root_config.contains("offline = true"));
    assert!(root_config.contains("[target.bpfel-unknown-none]"));
    assert!(root_config.contains("[target.x86_64-unknown-linux-musl]"));

    let nested_config = fs::read_to_string(workspace.join(".cargo/config.toml")).unwrap();
    assert!(nested_config.contains("directory = \"vendor\""));
    assert!(!nested_config.contains("[target."));
}
