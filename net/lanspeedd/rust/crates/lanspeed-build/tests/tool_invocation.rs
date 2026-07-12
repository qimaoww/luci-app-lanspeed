use std::{env, fs, os::unix::fs::PermissionsExt, path::Path};

use lanspeed_build::{build, BuildError, BuildTarget};

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn userspace_build_does_not_invoke_bpf_linker() {
    let tools = env::temp_dir().join(format!("lanspeed-build-tools-{}", std::process::id()));
    fs::create_dir_all(&tools).unwrap();
    let rustc = tools.join("rustc");
    let bpf_linker = tools.join("bpf-linker");
    let cargo = tools.join("cargo");
    let marker = tools.join("bpf-linker-invoked");
    let cargo_args = tools.join("cargo-args");

    write_executable(&rustc, "#!/bin/sh\nprintf 'rustc 1.94.0 (fake)\\n'\n");
    write_executable(
        &bpf_linker,
        "#!/bin/sh\nprintf invoked > \"$MARKER\"\nexit 99\n",
    );
    write_executable(
        &cargo,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CARGO_ARGS\"\nexit 0\n",
    );

    env::set_var("RUSTC", &rustc);
    env::set_var("BPF_LINKER", &bpf_linker);
    env::set_var("CARGO", &cargo);
    env::set_var("MARKER", &marker);
    env::set_var("CARGO_ARGS", &cargo_args);

    build(BuildTarget::Userspace).unwrap();
    assert!(!marker.exists());
    let args = fs::read_to_string(&cargo_args).unwrap();
    assert!(args
        .lines()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == ["--features", "openwrt"]));

    assert!(matches!(
        build(BuildTarget::Ebpf),
        Err(BuildError::CommandFailed {
            command: "bpf-linker",
            ..
        })
    ));
    assert!(marker.exists());

    fs::remove_dir_all(tools).unwrap();
}
