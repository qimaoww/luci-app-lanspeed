use lanspeed_build::{
    BuildError, ToolVersions, BPF_LINKER_ARCHIVE_SHA256, BPF_LINKER_ARCHIVE_URL,
    MAXIMUM_BPF_LINKER_EXCLUSIVE, MINIMUM_BPF_LINKER, MINIMUM_RUSTC, PINNED_BPF_LINKER,
};

#[test]
fn keeps_the_packaged_bpf_linker_archive_pinned() {
    assert_eq!(PINNED_BPF_LINKER, "0.10.3");
    assert_eq!(MINIMUM_BPF_LINKER, PINNED_BPF_LINKER);
    assert_eq!(MAXIMUM_BPF_LINKER_EXCLUSIVE, "0.11.0");
    assert_eq!(
        BPF_LINKER_ARCHIVE_URL,
        "https://github.com/aya-rs/bpf-linker/releases/download/v0.10.3/bpf-linker-x86_64-unknown-linux-musl.tar.gz"
    );
    assert_eq!(
        BPF_LINKER_ARCHIVE_SHA256,
        "0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c"
    );
}

#[test]
fn accepts_the_minimum_and_newer_stable_rust_toolchains() {
    assert_eq!(MINIMUM_RUSTC, "1.87.0");
    for rustc in ["1.87.0", "1.96.0", "1.97.1", "1.100.0"] {
        let versions = ToolVersions {
            rustc: rustc.into(),
            bpf_linker: PINNED_BPF_LINKER.into(),
        };
        assert!(
            versions.validate().is_ok(),
            "rustc {rustc} must be accepted"
        );
    }
}

#[test]
fn rejects_old_invalid_or_prerelease_rust_toolchains() {
    for rustc in ["1.86.99", "1.9.0"] {
        let versions = ToolVersions {
            rustc: rustc.into(),
            bpf_linker: PINNED_BPF_LINKER.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::VersionTooOld { name: "rustc", .. })
        ));
    }
    for rustc in ["", "1.96", "newest"] {
        let versions = ToolVersions {
            rustc: rustc.into(),
            bpf_linker: PINNED_BPF_LINKER.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::InvalidVersion { name: "rustc", .. })
        ));
    }
    let prerelease = ToolVersions {
        rustc: "1.96.0-nightly".into(),
        bpf_linker: PINNED_BPF_LINKER.into(),
    };
    assert!(matches!(
        prerelease.validate(),
        Err(BuildError::PrereleaseVersion { name: "rustc", .. })
    ));
}

#[test]
fn accepts_supported_stable_bpf_linker_versions() {
    for bpf_linker in ["0.10.3", "0.10.4", "0.10.99", "0.10.3+distribution.1"] {
        let versions = ToolVersions {
            rustc: "1.96.0".into(),
            bpf_linker: bpf_linker.into(),
        };
        assert!(
            versions.validate().is_ok(),
            "bpf-linker {bpf_linker} must be accepted"
        );
    }
}

#[test]
fn rejects_unsupported_bpf_linker_versions() {
    for bpf_linker in ["0.10.2", "0.9.99"] {
        let versions = ToolVersions {
            rustc: "1.96.0".into(),
            bpf_linker: bpf_linker.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::VersionTooOld {
                name: "bpf-linker",
                ..
            })
        ));
    }

    for bpf_linker in ["0.11.0", "0.11.1", "1.0.0"] {
        let versions = ToolVersions {
            rustc: "1.96.0".into(),
            bpf_linker: bpf_linker.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::VersionTooNew {
                name: "bpf-linker",
                ..
            })
        ));
    }

    for bpf_linker in ["0.10.3-rc.1", "0.10.4-alpha.1", "0.11.0-beta.1"] {
        let versions = ToolVersions {
            rustc: "1.96.0".into(),
            bpf_linker: bpf_linker.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::PrereleaseVersion {
                name: "bpf-linker",
                ..
            })
        ));
    }

    for bpf_linker in ["", "0.10", "current"] {
        let versions = ToolVersions {
            rustc: "1.96.0".into(),
            bpf_linker: bpf_linker.into(),
        };
        assert!(matches!(
            versions.validate(),
            Err(BuildError::InvalidVersion {
                name: "bpf-linker",
                ..
            })
        ));
    }
}
