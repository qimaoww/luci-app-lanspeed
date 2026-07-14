use lanspeed_build::{
    BuildError, ToolVersions, BPF_LINKER_ARCHIVE_SHA256, BPF_LINKER_ARCHIVE_URL,
    EXPECTED_BPF_LINKER, MINIMUM_RUSTC,
};

#[test]
fn accepts_the_minimum_and_newer_stable_rust_toolchains() {
    assert_eq!(MINIMUM_RUSTC, "1.94.0");
    assert_eq!(EXPECTED_BPF_LINKER, "0.10.3");
    assert_eq!(
        BPF_LINKER_ARCHIVE_URL,
        "https://github.com/aya-rs/bpf-linker/releases/download/v0.10.3/bpf-linker-x86_64-unknown-linux-musl.tar.gz"
    );
    assert_eq!(
        BPF_LINKER_ARCHIVE_SHA256,
        "0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c"
    );
    for rustc in ["1.94.0", "1.96.0", "1.100.0"] {
        let versions = ToolVersions {
            rustc: rustc.into(),
            bpf_linker: EXPECTED_BPF_LINKER.into(),
        };
        assert!(
            versions.validate().is_ok(),
            "rustc {rustc} must be accepted"
        );
    }
}

#[test]
fn rejects_old_invalid_or_prerelease_rust_toolchains() {
    for rustc in ["1.93.99", "1.9.0"] {
        let versions = ToolVersions {
            rustc: rustc.into(),
            bpf_linker: EXPECTED_BPF_LINKER.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::VersionTooOld { name: "rustc", .. })
        ));
    }
    for rustc in ["", "1.96", "newest"] {
        let versions = ToolVersions {
            rustc: rustc.into(),
            bpf_linker: EXPECTED_BPF_LINKER.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::InvalidVersion { name: "rustc", .. })
        ));
    }
    let prerelease = ToolVersions {
        rustc: "1.96.0-nightly".into(),
        bpf_linker: EXPECTED_BPF_LINKER.into(),
    };
    assert!(matches!(
        prerelease.validate(),
        Err(BuildError::PrereleaseVersion { name: "rustc", .. })
    ));
}

#[test]
fn keeps_bpf_linker_exactly_pinned() {
    for bpf_linker in ["0.10.2", "0.10.4"] {
        let versions = ToolVersions {
            rustc: "1.96.0".into(),
            bpf_linker: bpf_linker.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::VersionMismatch {
                name: "bpf-linker",
                ..
            })
        ));
    }
}
