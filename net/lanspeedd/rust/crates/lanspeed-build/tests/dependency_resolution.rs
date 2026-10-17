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
        (
            "rustc-literal-escaper-0.0.8",
            "rustc-literal-escaper",
            "0.0.8",
        ),
        // Rust 1.99.0 ships a `library/Cargo.lock` whose `-Z build-std` graph
        // needs newer pinned versions than the releases above.
        ("addr2line-0.27.1", "addr2line", "0.27.1"),
        ("dlmalloc-0.2.14", "dlmalloc", "0.2.14"),
        ("gimli-0.34.0", "gimli", "0.34.0"),
        ("libc-0.2.189", "libc", "0.2.189"),
        ("miniz_oxide-0.9.1", "miniz_oxide", "0.9.1"),
        ("moto-rt-0.16.4", "moto-rt", "0.16.4"),
        ("rand-0.9.5", "rand", "0.9.5"),
        ("rand_core-0.9.5", "rand_core", "0.9.5"),
        ("rustc-demangle-0.1.28", "rustc-demangle", "0.1.28"),
        ("unwinding-0.2.10", "unwinding", "0.2.10"),
        ("wasip2-1.0.4+wasi-0.2.12", "wasip2", "1.0.4+wasi-0.2.12"),
        ("wasip3-0.7.0+wasi-0.3.0", "wasip3", "0.7.0+wasi-0.3.0"),
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
        (
            "rustc-literal-escaper-0.0.8",
            "bfe6f213fb658c8fb95baabd5420393438cf5a98d707f5dd701d9197c705f71e",
        ),
        (
            "libc-0.2.189",
            "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2",
        ),
        (
            "rustc-demangle-0.1.28",
            "b74b56ffa8bb2830709a538c2cbcae9aa062db0d2a42563bfb09bdaae44020eb",
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
