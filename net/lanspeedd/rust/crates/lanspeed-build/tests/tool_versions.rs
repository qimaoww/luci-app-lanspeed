use lanspeed_build::{
    BuildError, ToolVersions, BPF_LINKER_ARCHIVE_SHA256, BPF_LINKER_ARCHIVE_URL,
    MAXIMUM_BPF_LINKER_EXCLUSIVE, MINIMUM_BPF_LINKER, MINIMUM_RUSTC, PINNED_BPF_LINKER,
};

#[test]
fn keeps_the_packaged_bpf_linker_archive_pinned() {
    assert_eq!(PINNED_BPF_LINKER, "0.11.1");
    assert_eq!(MINIMUM_BPF_LINKER, PINNED_BPF_LINKER);
    assert_eq!(MAXIMUM_BPF_LINKER_EXCLUSIVE, "0.12.0");
    assert_eq!(
        BPF_LINKER_ARCHIVE_URL,
        "https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst"
    );
    assert_eq!(
        BPF_LINKER_ARCHIVE_SHA256,
        "e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8"
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
    for bpf_linker in ["0.11.1", "0.11.2", "0.11.99", "0.11.1+distribution.1"] {
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
    for bpf_linker in ["0.11.0", "0.10.3", "0.9.99"] {
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

    for bpf_linker in ["0.12.0", "0.12.1", "1.0.0"] {
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

    for bpf_linker in ["0.11.1-rc.1", "0.11.2-alpha.1", "0.12.0-beta.1"] {
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
