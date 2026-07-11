use lanspeed_build::{
    ToolVersions, BPF_LINKER_ARCHIVE_SHA256, BPF_LINKER_ARCHIVE_URL, EXPECTED_BPF_LINKER,
    EXPECTED_RUSTC,
};

#[test]
fn accepts_only_the_pinned_toolchain() {
    let versions = ToolVersions {
        rustc: "1.94.0".into(),
        bpf_linker: "0.10.3".into(),
    };
    assert_eq!(EXPECTED_RUSTC, "1.94.0");
    assert_eq!(EXPECTED_BPF_LINKER, "0.10.3");
    assert_eq!(
        BPF_LINKER_ARCHIVE_URL,
        "https://github.com/aya-rs/bpf-linker/releases/download/v0.10.3/bpf-linker-x86_64-unknown-linux-musl.tar.gz"
    );
    assert_eq!(
        BPF_LINKER_ARCHIVE_SHA256,
        "0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c"
    );
    assert!(versions.validate().is_ok());
}
