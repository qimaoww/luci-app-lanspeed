use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    path::PathBuf,
    process::{Command, ExitStatus},
};

use semver::Version;
use thiserror::Error;

pub const MINIMUM_RUSTC: &str = env!("CARGO_PKG_RUST_VERSION");
/// Version pinned by the reproducible OpenWrt package download.
pub const PINNED_BPF_LINKER: &str = "0.10.3";
pub const MINIMUM_BPF_LINKER: &str = PINNED_BPF_LINKER;
pub const MAXIMUM_BPF_LINKER_EXCLUSIVE: &str = "0.11.0";
pub const BPF_LINKER_ARCHIVE_URL: &str = "https://github.com/aya-rs/bpf-linker/releases/download/v0.10.3/bpf-linker-x86_64-unknown-linux-musl.tar.gz";
pub const BPF_LINKER_ARCHIVE_SHA256: &str =
    "0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c";
pub const BPF_TARGET_ARCH_ENV: &str = "LANSPEED_BPF_TARGET_ARCH";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BpfTargetArch {
    Aarch64,
    X86_64,
}

impl BpfTargetArch {
    pub fn parse(value: &OsStr) -> Result<Self, BuildError> {
        let value = value
            .to_str()
            .ok_or_else(|| BuildError::InvalidBpfTargetArch(value.to_os_string()))?;
        match value {
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            "x86_64" | "amd64" => Ok(Self::X86_64),
            _ if value.starts_with("aarch64-") => Ok(Self::Aarch64),
            _ if value.starts_with("x86_64-") => Ok(Self::X86_64),
            _ => Err(BuildError::InvalidBpfTargetArch(value.into())),
        }
    }

    const fn aya_name(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::X86_64 => "x86_64",
        }
    }

    const fn builds_ecm(self) -> bool {
        matches!(self, Self::Aarch64)
    }

    const fn tc_feature(self) -> &'static str {
        match self {
            Self::Aarch64 => "nss-tc",
            Self::X86_64 => "x86-tc",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ToolVersions {
    pub rustc: String,
    pub bpf_linker: String,
}

impl ToolVersions {
    pub fn detect() -> Result<Self, BuildError> {
        Ok(Self {
            rustc: detect_rustc()?,
            bpf_linker: detect_bpf_linker()?,
        })
    }

    pub fn validate(&self) -> Result<(), BuildError> {
        validate_minimum_version("rustc", &self.rustc, MINIMUM_RUSTC)?;
        validate_version_range(
            "bpf-linker",
            &self.bpf_linker,
            MINIMUM_BPF_LINKER,
            MAXIMUM_BPF_LINKER_EXCLUSIVE,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildTarget {
    Userspace,
    Ebpf,
}

impl BuildTarget {
    pub fn parse(value: &OsStr) -> Result<Self, BuildError> {
        match value.to_str() {
            Some("build-userspace") => Ok(Self::Userspace),
            Some("build-ebpf") => Ok(Self::Ebpf),
            _ => Err(BuildError::Usage),
        }
    }
}

pub fn build(target: BuildTarget) -> Result<(), BuildError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let workspace = workspace_root();
    let target_dir = target_dir(&workspace);
    match target {
        BuildTarget::Userspace => {
            validate_minimum_version("rustc", &detect_rustc()?, MINIMUM_RUSTC)?;
            let userspace_target = env::var_os("LANSPEED_USERSPACE_TARGET")
                .ok_or(BuildError::MissingUserspaceTarget)?;
            let mut command = Command::new(&cargo);
            command.current_dir(&workspace).arg("build");
            command.env_remove("RUSTC_BOOTSTRAP");
            command.args(["-p", "lanspeedd", "--release", "--target"]);
            command.arg(userspace_target);
            command.args(["--features", "openwrt", "--locked", "--offline"]);
            ensure_success(command.status()?, target)
        }
        BuildTarget::Ebpf => {
            ToolVersions::detect()?.validate()?;
            let target_arch = BpfTargetArch::parse(
                &env::var_os(BPF_TARGET_ARCH_ENV).ok_or(BuildError::MissingBpfTargetArch)?,
            )?;
            let kfunc_features = format!("{},conntrack-kfunc", target_arch.tc_feature());
            let kfunc = build_ebpf_variant(
                &cargo,
                &workspace,
                &target_dir,
                "kfunc",
                &kfunc_features,
                target_arch,
            )?;
            let fallback = build_ebpf_variant(
                &cargo,
                &workspace,
                &target_dir,
                "fallback",
                target_arch.tc_feature(),
                target_arch,
            )?;
            let output_dir = target_dir.join("bpfel-unknown-none/release");
            fs::create_dir_all(&output_dir)?;
            fs::copy(&kfunc, output_dir.join("lanspeed-ebpf-kfunc"))?;
            fs::copy(&fallback, output_dir.join("lanspeed-ebpf-fallback"))?;
            fs::copy(&kfunc, output_dir.join("lanspeed-ebpf"))?;
            let ecm_output = output_dir.join("lanspeed-ebpf-ecm");
            if target_arch.builds_ecm() {
                let ecm = build_ebpf_variant(
                    &cargo,
                    &workspace,
                    &target_dir,
                    "ecm-aarch64",
                    "nss-ecm",
                    target_arch,
                )?;
                fs::copy(ecm, ecm_output)?;
            } else if let Err(error) = fs::remove_file(ecm_output) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error.into());
                }
            }
            Ok(())
        }
    }
}

fn build_ebpf_variant(
    cargo: &OsStr,
    workspace: &PathBuf,
    target_root: &PathBuf,
    variant: &str,
    features: &str,
    target_arch: BpfTargetArch,
) -> Result<PathBuf, BuildError> {
    let target_dir = target_root.join(format!("lanspeed-ebpf-{variant}"));
    let mut command = Command::new(cargo);
    command.current_dir(workspace).args([
        "build",
        "-p",
        "lanspeed-ebpf",
        "--release",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--no-default-features",
        "--features",
        features,
        "--locked",
        "--offline",
    ]);
    command.arg("--target-dir").arg(&target_dir);
    command.env("RUSTC_BOOTSTRAP", "1");
    command.env("AYA_BPF_TARGET_ARCH", target_arch.aya_name());
    if let Some(linker) = env::var_os("BPF_LINKER") {
        command.env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER", linker);
    }
    ensure_success(command.status()?, BuildTarget::Ebpf)?;
    Ok(target_dir.join("bpfel-unknown-none/release/lanspeed-ebpf"))
}

fn detect_rustc() -> Result<String, BuildError> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    command_version(&rustc, "rustc")
}

fn detect_bpf_linker() -> Result<String, BuildError> {
    let bpf_linker = env::var_os("BPF_LINKER").unwrap_or_else(|| OsString::from("bpf-linker"));
    command_version(&bpf_linker, "bpf-linker")
}

fn command_version(command: &OsStr, name: &'static str) -> Result<String, BuildError> {
    let output = Command::new(command).arg("--version").output()?;
    if !output.status.success() {
        return Err(BuildError::CommandFailed {
            command: name,
            status: output.status,
        });
    }
    let output = String::from_utf8(output.stdout)?;
    output
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .ok_or(BuildError::InvalidVersionOutput(name))
}

fn validate_minimum_version(
    name: &'static str,
    actual: &str,
    minimum: &'static str,
) -> Result<(), BuildError> {
    let actual_version = Version::parse(actual).map_err(|source| BuildError::InvalidVersion {
        name,
        actual: actual.to_owned(),
        source,
    })?;
    if !actual_version.pre.is_empty() {
        return Err(BuildError::PrereleaseVersion {
            name,
            actual: actual.to_owned(),
        });
    }
    let minimum_version =
        Version::parse(minimum).expect("the minimum Rust version constant must be valid semver");
    if actual_version >= minimum_version {
        Ok(())
    } else {
        Err(BuildError::VersionTooOld {
            name,
            minimum,
            actual: actual.to_owned(),
        })
    }
}

fn validate_version_range(
    name: &'static str,
    actual: &str,
    minimum: &'static str,
    maximum_exclusive: &'static str,
) -> Result<(), BuildError> {
    let actual_version = Version::parse(actual).map_err(|source| BuildError::InvalidVersion {
        name,
        actual: actual.to_owned(),
        source,
    })?;
    if !actual_version.pre.is_empty() {
        return Err(BuildError::PrereleaseVersion {
            name,
            actual: actual.to_owned(),
        });
    }
    let minimum_version =
        Version::parse(minimum).expect("the minimum tool version constant must be valid semver");
    let maximum_version = Version::parse(maximum_exclusive)
        .expect("the maximum tool version constant must be valid semver");
    if actual_version < minimum_version {
        Err(BuildError::VersionTooOld {
            name,
            minimum,
            actual: actual.to_owned(),
        })
    } else if actual_version >= maximum_version {
        Err(BuildError::VersionTooNew {
            name,
            maximum_exclusive,
            actual: actual.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn workspace_root() -> PathBuf {
    if let Some(workspace) = env::var_os("LANSPEED_BUILD_WORKSPACE") {
        return PathBuf::from(workspace);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("lanspeed-build must remain below rust/crates")
        .to_owned()
}

fn target_dir(workspace: &PathBuf) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR").map(PathBuf::from) {
        Some(target_dir) if target_dir.is_absolute() => target_dir,
        Some(target_dir) => workspace.join(target_dir),
        None => workspace.join("target"),
    }
}

fn ensure_success(status: ExitStatus, target: BuildTarget) -> Result<(), BuildError> {
    if status.success() {
        Ok(())
    } else {
        Err(BuildError::BuildFailed { target, status })
    }
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("usage: lanspeed-build <build-userspace|build-ebpf>")]
    Usage,
    #[error("LANSPEED_USERSPACE_TARGET is required for userspace builds")]
    MissingUserspaceTarget,
    #[error("LANSPEED_BPF_TARGET_ARCH is required for eBPF builds")]
    MissingBpfTargetArch,
    #[error("unsupported eBPF target architecture {0:?}; expected aarch64 or x86_64")]
    InvalidBpfTargetArch(OsString),
    #[error("{name} must be at least {minimum}, found {actual}")]
    VersionTooOld {
        name: &'static str,
        minimum: &'static str,
        actual: String,
    },
    #[error("{name} must be earlier than {maximum_exclusive}, found {actual}")]
    VersionTooNew {
        name: &'static str,
        maximum_exclusive: &'static str,
        actual: String,
    },
    #[error("{name} prerelease versions are not supported, found {actual}")]
    PrereleaseVersion { name: &'static str, actual: String },
    #[error("invalid {name} version {actual}: {source}")]
    InvalidVersion {
        name: &'static str,
        actual: String,
        source: semver::Error,
    },
    #[error("invalid version output from {0}")]
    InvalidVersionOutput(&'static str),
    #[error("{command} --version failed with {status}")]
    CommandFailed {
        command: &'static str,
        status: ExitStatus,
    },
    #[error("{target:?} build failed with {status}")]
    BuildFailed {
        target: BuildTarget,
        status: ExitStatus,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_stable_bpf_linker_versions() {
        for bpf_linker in ["0.10.3", "0.10.4", "0.10.99", "0.10.3+distribution.1"] {
            let versions = ToolVersions {
                rustc: MINIMUM_RUSTC.into(),
                bpf_linker: bpf_linker.into(),
            };

            assert!(
                versions.validate().is_ok(),
                "bpf-linker {bpf_linker} must be accepted"
            );
        }
    }

    #[test]
    fn rejects_bpf_linker_outside_the_supported_series() {
        for bpf_linker in ["0.10.2", "0.9.99"] {
            let versions = ToolVersions {
                rustc: MINIMUM_RUSTC.into(),
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
                rustc: MINIMUM_RUSTC.into(),
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
    }

    #[test]
    fn rejects_prerelease_bpf_linker_versions() {
        for bpf_linker in ["0.10.3-rc.1", "0.10.4-alpha.1", "0.11.0-beta.1"] {
            let versions = ToolVersions {
                rustc: MINIMUM_RUSTC.into(),
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
    }

    #[test]
    fn parses_only_supported_subcommands() {
        assert_eq!(
            BuildTarget::parse(OsStr::new("build-userspace")).unwrap(),
            BuildTarget::Userspace
        );
        assert_eq!(
            BuildTarget::parse(OsStr::new("build-ebpf")).unwrap(),
            BuildTarget::Ebpf
        );
        assert!(matches!(
            BuildTarget::parse(OsStr::new("build-all")),
            Err(BuildError::Usage)
        ));
    }

    #[test]
    fn separates_x86_tc_from_aarch64_nss_ecm_objects() {
        for value in ["x86_64", "amd64", "x86_64-openwrt-linux-musl"] {
            let arch = BpfTargetArch::parse(OsStr::new(value)).unwrap();
            assert_eq!(arch, BpfTargetArch::X86_64);
            assert!(!arch.builds_ecm());
            assert_eq!(arch.aya_name(), "x86_64");
        }
        for value in ["aarch64", "arm64", "aarch64-openwrt-linux-musl"] {
            let arch = BpfTargetArch::parse(OsStr::new(value)).unwrap();
            assert_eq!(arch, BpfTargetArch::Aarch64);
            assert!(arch.builds_ecm());
            assert_eq!(arch.aya_name(), "aarch64");
        }
        assert!(BpfTargetArch::parse(OsStr::new("mips64")).is_err());
    }
}
