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
    let workspace = tools.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    write_executable(&rustc, "#!/bin/sh\nprintf 'rustc 1.94.0 (fake)\\n'\n");
    write_executable(
        &bpf_linker,
        "#!/bin/sh\nprintf invoked > \"$MARKER\"\nexit 99\n",
    );
    write_executable(
        &cargo,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CARGO_ARGS\"\nexit 0\n",
    );

    let mut variables = Environment::new();
    variables.set("RUSTC", &rustc);
    variables.set("BPF_LINKER", &bpf_linker);
    variables.set("CARGO", &cargo);
    variables.set("MARKER", &marker);
    variables.set("CARGO_ARGS", &cargo_args);
    variables.set("LANSPEED_BUILD_WORKSPACE", &workspace);
    variables.set("LANSPEED_USERSPACE_TARGET", "aarch64-unknown-linux-musl");

    build(BuildTarget::Userspace).unwrap();
    assert!(!marker.exists());
    let args = fs::read_to_string(&cargo_args).unwrap();
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--features", "openwrt"]));
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--target", "aarch64-unknown-linux-musl"]));

    assert!(matches!(
        build(BuildTarget::Ebpf),
        Err(BuildError::CommandFailed {
            command: "bpf-linker",
            ..
        })
    ));
    assert!(marker.exists());
}

#[derive(Debug)]
struct CargoInvocation {
    args: Vec<String>,
    working_directory: PathBuf,
    bootstrap: String,
    linker: String,
}

fn parse_invocations(log: &str) -> Vec<CargoInvocation> {
    log.split("---\n")
        .filter(|record| !record.trim().is_empty())
        .map(|record| {
            let mut args = Vec::new();
            let mut working_directory = None;
            let mut bootstrap = None;
            let mut linker = None;
            for line in record.lines() {
                if let Some(value) = line.strip_prefix("ARG=") {
                    args.push(value.to_owned());
                } else if let Some(value) = line.strip_prefix("PWD=") {
                    working_directory = Some(PathBuf::from(value));
                } else if let Some(value) = line.strip_prefix("BOOTSTRAP=") {
                    bootstrap = Some(value.to_owned());
                } else if let Some(value) = line.strip_prefix("LINKER=") {
                    linker = Some(value.to_owned());
                }
            }
            CargoInvocation {
                args,
                working_directory: working_directory.expect("fake cargo must log PWD"),
                bootstrap: bootstrap.expect("fake cargo must log RUSTC_BOOTSTRAP"),
                linker: linker.expect("fake cargo must log linker"),
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
fn ebpf_build_invokes_both_variants_and_copies_all_objects() {
    let _lock = environment_lock();
    let tools = TempDir::new("ebpf");
    let rustc = tools.path().join("rustc");
    let bpf_linker = tools.path().join("bpf-linker");
    let cargo = tools.path().join("cargo");
    let cargo_log = tools.path().join("cargo.log");
    let workspace = tools.path().join("workspace");
    fs::create_dir_all(&workspace).unwrap();

    write_executable(&rustc, "#!/bin/sh\nprintf 'rustc 1.94.0 (fake)\\n'\n");
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

expected_prefix="${LANSPEED_BUILD_WORKSPACE%/}/target/"
case "$target_dir" in
    "$expected_prefix"*) ;;
    *) exit 0 ;;
esac

flavor=kfunc
for arg
do
    if [ "$arg" = '--no-default-features' ]; then
        flavor=fallback
    fi
done

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

    build(BuildTarget::Ebpf).unwrap();

    let invocations = parse_invocations(&fs::read_to_string(&cargo_log).unwrap());
    assert_eq!(
        invocations.len(),
        2,
        "expected kfunc and fallback Cargo calls"
    );
    assert_eq!(invocations[0].working_directory, workspace);
    assert_eq!(invocations[1].working_directory, workspace);
    assert_eq!(invocations[0].bootstrap, "1");
    assert_eq!(invocations[1].bootstrap, "1");
    assert_eq!(invocations[0].linker, bpf_linker.to_string_lossy());
    assert_eq!(invocations[1].linker, bpf_linker.to_string_lossy());

    assert!(has_pair(&invocations[0].args, "-Z", "build-std=core"));
    assert!(has_pair(&invocations[1].args, "-Z", "build-std=core"));
    assert!(!has_arg(&invocations[0].args, "--no-default-features"));
    assert!(has_arg(&invocations[1].args, "--no-default-features"));

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
            workspace.join("target/lanspeed-ebpf-kfunc"),
            workspace.join("target/lanspeed-ebpf-fallback"),
        ]
    );
    assert_ne!(target_dirs[0], target_dirs[1]);

    let output_dir = workspace.join("target/bpfel-unknown-none/release");
    let mut output_names = fs::read_dir(&output_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    output_names.sort();
    assert_eq!(
        output_names,
        vec![
            OsString::from("lanspeed-ebpf"),
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
}
