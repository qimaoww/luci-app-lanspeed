use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    path::PathBuf,
    process::{Command, ExitStatus},
};

use thiserror::Error;

pub const EXPECTED_RUSTC: &str = "1.94.0";
pub const EXPECTED_BPF_LINKER: &str = "0.10.3";
pub const BPF_LINKER_ARCHIVE_URL: &str = "https://github.com/aya-rs/bpf-linker/releases/download/v0.10.3/bpf-linker-x86_64-unknown-linux-musl.tar.gz";
pub const BPF_LINKER_ARCHIVE_SHA256: &str =
    "0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c";

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
        validate_version("rustc", &self.rustc, EXPECTED_RUSTC)?;
        validate_version("bpf-linker", &self.bpf_linker, EXPECTED_BPF_LINKER)
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
    match target {
        BuildTarget::Userspace => {
            validate_version("rustc", &detect_rustc()?, EXPECTED_RUSTC)?;
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
            let kfunc = build_ebpf_variant(&cargo, &workspace, "kfunc", false)?;
            let fallback = build_ebpf_variant(&cargo, &workspace, "fallback", true)?;
            let output_dir = workspace.join("target/bpfel-unknown-none/release");
            fs::create_dir_all(&output_dir)?;
            fs::copy(&kfunc, output_dir.join("lanspeed-ebpf-kfunc"))?;
            fs::copy(&fallback, output_dir.join("lanspeed-ebpf-fallback"))?;
            fs::copy(kfunc, output_dir.join("lanspeed-ebpf"))?;
            Ok(())
        }
    }
}

fn build_ebpf_variant(
    cargo: &OsStr,
    workspace: &PathBuf,
    variant: &str,
    fallback: bool,
) -> Result<PathBuf, BuildError> {
    let target_dir = workspace
        .join("target")
        .join(format!("lanspeed-ebpf-{variant}"));
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
        "--locked",
        "--offline",
    ]);
    command.arg("--target-dir").arg(&target_dir);
    if fallback {
        command.arg("--no-default-features");
    }
    command.env("RUSTC_BOOTSTRAP", "1");
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

fn validate_version(
    name: &'static str,
    actual: &str,
    expected: &'static str,
) -> Result<(), BuildError> {
    if actual == expected {
        Ok(())
    } else {
        Err(BuildError::VersionMismatch {
            name,
            expected,
            actual: actual.to_owned(),
        })
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
    #[error("{name} must be {expected}, found {actual}")]
    VersionMismatch {
        name: &'static str,
        expected: &'static str,
        actual: String,
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
    fn rejects_an_unpinned_version() {
        let versions = ToolVersions {
            rustc: EXPECTED_RUSTC.into(),
            bpf_linker: "0.10.2".into(),
        };

        assert!(matches!(
            versions.validate(),
            Err(BuildError::VersionMismatch {
                name: "bpf-linker",
                ..
            })
        ));
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
}
