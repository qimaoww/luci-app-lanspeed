use std::{
    env,
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use lanspeed_build::{build, BuildError, BuildTarget};

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "lanspeed-build-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Environment {
    saved: Vec<(String, Option<OsString>)>,
}

impl Environment {
    fn new() -> Self {
        Self { saved: Vec::new() }
    }

    fn remember(&mut self, key: &str) {
        if self.saved.iter().any(|(saved, _)| saved == key) {
            return;
        }
        self.saved.push((key.to_owned(), env::var_os(key)));
    }

    fn set(&mut self, key: &str, value: impl AsRef<std::ffi::OsStr>) {
        self.remember(key);
        env::set_var(key, value);
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..).rev() {
            match value {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
    }
}

fn environment_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn userspace_build_does_not_invoke_bpf_linker() {
    let _lock = environment_lock();
    let tools = TempDir::new("userspace");
    let rustc = tools.path().join("rustc");
    let bpf_linker = tools.path().join("bpf-linker");
    let cargo = tools.path().join("cargo");
    let marker = tools.path().join("bpf-linker-invoked");
    let cargo_args = tools.path().join("cargo-args");
    let bootstrap = tools.path().join("cargo-bootstrap");
    let workspace = tools.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    write_executable(&rustc, "#!/bin/sh\nprintf 'rustc 1.96.0 (fake)\\n'\n");
    write_executable(
        &bpf_linker,
        "#!/bin/sh\nprintf invoked > \"$MARKER\"\nexit 99\n",
    );
    write_executable(
        &cargo,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CARGO_ARGS\"\nprintf '%s\\n' \"${RUSTC_BOOTSTRAP-}\" > \"$BOOTSTRAP\"\nexit 0\n",
    );

    let mut variables = Environment::new();
    variables.set("RUSTC", &rustc);
    variables.set("BPF_LINKER", &bpf_linker);
    variables.set("CARGO", &cargo);
    variables.set("MARKER", &marker);
    variables.set("CARGO_ARGS", &cargo_args);
    variables.set("BOOTSTRAP", &bootstrap);
    variables.set("LANSPEED_BUILD_WORKSPACE", &workspace);
    variables.set("LANSPEED_USERSPACE_TARGET", "aarch64-unknown-linux-musl");

    build(BuildTarget::Userspace).unwrap();
    assert!(!marker.exists());
    let args = fs::read_to_string(&cargo_args).unwrap();
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--no-default-features", "--features"]));
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--features", "openwrt,nss-platform"]));
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--target", "aarch64-unknown-linux-musl"]));
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["-Z", "build-std=std,panic_unwind"]));
    assert_eq!(fs::read_to_string(&bootstrap).unwrap().trim(), "1");

    assert!(matches!(
        build(BuildTarget::Ebpf),
        Err(BuildError::CommandFailed {
            command: "bpf-linker",
            ..
        })
    ));
    assert!(marker.exists());
}

#[test]
fn x86_userspace_build_excludes_nss_platform() {
    let _lock = environment_lock();
    let tools = TempDir::new("userspace-x86");
    let rustc = tools.path().join("rustc");
    let cargo = tools.path().join("cargo");
    let cargo_args = tools.path().join("cargo-args");
    let workspace = tools.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    write_executable(&rustc, "#!/bin/sh\nprintf 'rustc 1.96.0 (fake)\\n'\n");
    write_executable(
        &cargo,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CARGO_ARGS\"\nexit 0\n",
    );
    let mut variables = Environment::new();
    variables.set("RUSTC", &rustc);
    variables.set("CARGO", &cargo);
    variables.set("CARGO_ARGS", &cargo_args);
    variables.set("LANSPEED_BUILD_WORKSPACE", &workspace);
    variables.set("LANSPEED_USERSPACE_TARGET", "x86_64-unknown-linux-musl");

    build(BuildTarget::Userspace).unwrap();
    let args = fs::read_to_string(&cargo_args).unwrap();
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--features", "openwrt"]));
    assert!(!args.contains("nss-platform"));
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--no-default-features", "--features"]));
}

#[test]
fn userspace_build_rejects_an_old_rustc_before_invoking_cargo() {
    let _lock = environment_lock();
    let tools = TempDir::new("old-rustc");
    let rustc = tools.path().join("rustc");
    let cargo = tools.path().join("cargo");
    let marker = tools.path().join("cargo-invoked");
    let workspace = tools.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    write_executable(&rustc, "#!/bin/sh\nprintf 'rustc 1.86.99 (fake)\\n'\n");
    write_executable(&cargo, "#!/bin/sh\nprintf invoked > \"$MARKER\"\nexit 0\n");

    let mut variables = Environment::new();
    variables.set("RUSTC", &rustc);
    variables.set("CARGO", &cargo);
    variables.set("MARKER", &marker);
    variables.set("LANSPEED_BUILD_WORKSPACE", &workspace);
    variables.set("LANSPEED_USERSPACE_TARGET", "aarch64-unknown-linux-musl");

    assert!(matches!(
        build(BuildTarget::Userspace),
        Err(BuildError::VersionTooOld { name: "rustc", .. })
    ));
    assert!(!marker.exists());
}

#[derive(Debug)]
struct CargoInvocation {
    args: Vec<String>,
    working_directory: PathBuf,
    bootstrap: String,
    linker: String,
    aya_arch: String,
}

fn parse_invocations(log: &str) -> Vec<CargoInvocation> {
    log.split("---\n")
        .filter(|record| !record.trim().is_empty())
        .map(|record| {
            let mut args = Vec::new();
            let mut working_directory = None;
            let mut bootstrap = None;
            let mut linker = None;
            let mut aya_arch = None;
            for line in record.lines() {
                if let Some(value) = line.strip_prefix("ARG=") {
                    args.push(value.to_owned());
                } else if let Some(value) = line.strip_prefix("PWD=") {
                    working_directory = Some(PathBuf::from(value));
                } else if let Some(value) = line.strip_prefix("BOOTSTRAP=") {
                    bootstrap = Some(value.to_owned());
                } else if let Some(value) = line.strip_prefix("LINKER=") {
                    linker = Some(value.to_owned());
                } else if let Some(value) = line.strip_prefix("AYA_ARCH=") {
                    aya_arch = Some(value.to_owned());
                }
            }
            CargoInvocation {
                args,
                working_directory: working_directory.expect("fake cargo must log PWD"),
                bootstrap: bootstrap.expect("fake cargo must log RUSTC_BOOTSTRAP"),
                linker: linker.expect("fake cargo must log linker"),
                aya_arch: aya_arch.expect("fake cargo must log AYA_BPF_TARGET_ARCH"),
            }
        })
        .collect()
}

fn has_arg(args: &[String], expected: &str) -> bool {
    args.iter().any(|arg| arg == expected)
}

fn has_pair(args: &[String], first: &str, second: &str) -> bool {
    args.windows(2)
        .any(|pair| pair[0] == first && pair[1] == second)
}

#[test]
fn ebpf_build_separates_x86_tc_and_aarch64_nss_objects() {
    let _lock = environment_lock();
    let tools = TempDir::new("ebpf");
    let rustc = tools.path().join("rustc");
    let bpf_linker = tools.path().join("bpf-linker");
    let cargo = tools.path().join("cargo");
    let cargo_log = tools.path().join("cargo.log");
    let workspace = tools.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    write_executable(&rustc, "#!/bin/sh\nprintf 'rustc 1.100.0 (fake)\\n'\n");
    write_executable(
        &bpf_linker,
        "#!/bin/sh\nprintf 'bpf-linker 0.10.3 (fake)\\n'\n",
    );
    write_executable(
        &cargo,
        r##"#!/bin/sh
set -eu
{
    printf 'PWD=%s\n' "$PWD"
    printf 'BOOTSTRAP=%s\n' "${RUSTC_BOOTSTRAP-}"
    printf 'LINKER=%s\n' "${CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER-}"
    printf 'AYA_ARCH=%s\n' "${AYA_BPF_TARGET_ARCH-}"
    for arg
    do
        printf 'ARG=%s\n' "$arg"
    done
    printf '%s\n' '---'
} >> "$CARGO_LOG"

target_dir=
previous=
for arg
do
    if [ "$previous" = '--target-dir' ]; then
        target_dir="$arg"
    fi
    previous="$arg"
done

expected_prefix="${CARGO_TARGET_DIR%/}/"
case "$target_dir" in
    "$expected_prefix"*) ;;
    *) exit 0 ;;
esac

flavor=
previous=
for arg
do
    if [ "$previous" = '--features' ]; then
        case "$arg" in
            x86-tc,conntrack-kfunc|nss-tc,conntrack-kfunc) flavor=kfunc ;;
            x86-tc|nss-tc) flavor=fallback ;;
            nss-ecm) flavor=ecm ;;
            *) exit 90 ;;
        esac
    fi
    previous="$arg"
done
[ -n "$flavor" ] || exit 91

output="$target_dir/bpfel-unknown-none/release/lanspeed-ebpf"
mkdir -p "$(dirname "$output")"
printf '%s\n' "$flavor" > "$output"
exit 0
"##,
    );

    let mut variables = Environment::new();
    variables.set("RUSTC", &rustc);
    variables.set("BPF_LINKER", &bpf_linker);
    variables.set("CARGO", &cargo);
    variables.set("CARGO_LOG", &cargo_log);
    variables.set("LANSPEED_BUILD_WORKSPACE", &workspace);
    variables.set("LANSPEED_BPF_TARGET_ARCH", "aarch64");
    let target_root = workspace.join("matrix-target");
    variables.set("CARGO_TARGET_DIR", &target_root);

    build(BuildTarget::Ebpf).unwrap();

    let invocations = parse_invocations(&fs::read_to_string(&cargo_log).unwrap());
    assert_eq!(
        invocations.len(),
        3,
        "aarch64 must build kfunc TC, fallback TC, and isolated ECM objects"
    );
    assert_eq!(invocations[0].working_directory, workspace);
    assert_eq!(invocations[1].working_directory, workspace);
    assert_eq!(invocations[2].working_directory, workspace);
    assert_eq!(invocations[0].bootstrap, "1");
    assert_eq!(invocations[1].bootstrap, "1");
    assert_eq!(invocations[2].bootstrap, "1");
    assert_eq!(invocations[0].linker, bpf_linker.to_string_lossy());
    assert_eq!(invocations[1].linker, bpf_linker.to_string_lossy());
    assert_eq!(invocations[2].linker, bpf_linker.to_string_lossy());
    assert!(invocations
        .iter()
        .all(|invocation| invocation.aya_arch == "aarch64"));

    assert!(has_pair(&invocations[0].args, "-Z", "build-std=core"));
    assert!(has_pair(&invocations[1].args, "-Z", "build-std=core"));
    assert!(has_pair(&invocations[2].args, "-Z", "build-std=core"));
    assert!(invocations
        .iter()
        .all(|invocation| has_arg(&invocation.args, "--no-default-features")));
    assert!(has_pair(
        &invocations[0].args,
        "--features",
        "nss-tc,conntrack-kfunc"
    ));
    assert!(has_pair(&invocations[1].args, "--features", "nss-tc"));
    assert!(has_pair(&invocations[2].args, "--features", "nss-ecm"));

    let target_dirs = invocations
        .iter()
        .map(|invocation| {
            invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "--target-dir")
                .map(|pair| PathBuf::from(&pair[1]))
                .expect("each eBPF call must select a target directory")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        target_dirs,
        vec![
            target_root.join("lanspeed-ebpf-kfunc"),
            target_root.join("lanspeed-ebpf-fallback"),
            target_root.join("lanspeed-ebpf-ecm-aarch64"),
        ]
    );
    assert_ne!(target_dirs[0], target_dirs[1]);

    let output_dir = target_root.join("bpfel-unknown-none/release");
    let mut output_names = fs::read_dir(&output_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    output_names.sort();
    assert_eq!(
        output_names,
        vec![
            OsString::from("lanspeed-ebpf"),
            OsString::from("lanspeed-ebpf-ecm"),
            OsString::from("lanspeed-ebpf-fallback"),
            OsString::from("lanspeed-ebpf-kfunc"),
        ]
    );
    assert_eq!(
        fs::read_to_string(output_dir.join("lanspeed-ebpf-kfunc")).unwrap(),
        "kfunc\n"
    );
    assert_eq!(
        fs::read_to_string(output_dir.join("lanspeed-ebpf-fallback")).unwrap(),
        "fallback\n"
    );
    assert_eq!(
        fs::read_to_string(output_dir.join("lanspeed-ebpf")).unwrap(),
        "kfunc\n"
    );
    assert_eq!(
        fs::read_to_string(output_dir.join("lanspeed-ebpf-ecm")).unwrap(),
        "ecm\n"
    );

    variables.set("LANSPEED_BPF_TARGET_ARCH", "x86_64");
    build(BuildTarget::Ebpf).unwrap();
    let all_invocations = parse_invocations(&fs::read_to_string(&cargo_log).unwrap());
    let x86_invocations = &all_invocations[3..];
    assert_eq!(x86_invocations.len(), 2, "x86 must build TC objects only");
    assert!(x86_invocations
        .iter()
        .all(|invocation| invocation.aya_arch == "x86_64"));
    assert!(x86_invocations.iter().all(|invocation| {
        has_pair(&invocation.args, "--features", "x86-tc")
            || has_pair(&invocation.args, "--features", "x86-tc,conntrack-kfunc")
    }));
    assert!(
        !output_dir.join("lanspeed-ebpf-ecm").exists(),
        "x86 build must remove a stale NSS ECM object"
    );
}
