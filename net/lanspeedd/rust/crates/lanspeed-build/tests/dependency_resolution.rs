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
    assert!(
        !root_config.contains("[target.bpfel-unknown-none]"),
        "the repository config must not duplicate workspace BPF rustflags because Cargo merges parent and child arrays"
    );
    assert!(root_config.contains("[target.x86_64-unknown-linux-musl]"));

    let nested_config = fs::read_to_string(workspace.join(".cargo/config.toml")).unwrap();
    assert!(nested_config.contains("directory = \"vendor\""));
    assert!(nested_config.contains("[target.bpfel-unknown-none]"));
    let packaged_bpf_config = nested_config
        .split("[target.bpfel-unknown-none]")
        .nth(1)
        .unwrap()
        .split("[target.")
        .next()
        .unwrap();
    assert!(packaged_bpf_config.contains("linker = \"bpf-linker\""));
    let packaged_bpf_rustflags = packaged_bpf_config
        .lines()
        .find(|line| line.trim_start().starts_with("rustflags ="))
        .unwrap();
    assert!(packaged_bpf_rustflags.contains("\"debuginfo=2\""));
    assert!(packaged_bpf_rustflags.contains("\"link-arg=--btf\""));
    assert!(!nested_config.contains("[target.x86_64-unknown-linux-musl]"));
}

#[test]
fn vendors_build_std_dependencies_for_supported_rust_releases() {
    let workspace = workspace_root();
    for (directory, name, version) in [
        ("libc-0.2.178", "libc", "0.2.178"),
        ("rustc-demangle", "rustc-demangle", "0.1.26"),
        ("libc-0.2.183", "libc", "0.2.183"),
        ("rustc-demangle-0.1.27", "rustc-demangle", "0.1.27"),
    ] {
        let manifest =
            fs::read_to_string(workspace.join("vendor").join(directory).join("Cargo.toml"))
                .unwrap_or_else(|error| panic!("missing vendored {name} {version}: {error}"));
        let package = manifest
            .split_once("[package]")
            .map(|(_, package)| package)
            .unwrap_or_else(|| panic!("vendored {name} {version} has no package section"));
        assert!(
            package.contains(&format!("name = \"{name}\"")),
            "vendored directory {directory} must contain {name}"
        );
        assert!(
            package.contains(&format!("version = \"{version}\"")),
            "vendored directory {directory} must contain version {version}"
        );
    }

    for (directory, checksum) in [
        (
            "libc-0.2.183",
            "b5b646652bf6661599e1da8901b3b9522896f01e736bad5f723fe7a3a27f899d",
        ),
        (
            "rustc-demangle-0.1.27",
            "b50b8869d9fc858ce7266cce0194bd74df58b9d0e3f6df3a9fc8eb470d95c09d",
        ),
    ] {
        let checksums = fs::read_to_string(
            workspace
                .join("vendor")
                .join(directory)
                .join(".cargo-checksum.json"),
        )
        .unwrap();
        assert!(
            checksums.contains(&format!("\"package\":\"{checksum}\"")),
            "vendored directory {directory} must retain its crates.io checksum"
        );
    }
}
