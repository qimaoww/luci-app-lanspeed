use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use lanspeedd::collectors::bpf::runtime::{AttachMode, AyaAdapter, BpfRuntime, SystemAyaAdapter};

struct TestNetwork {
    host: String,
    namespace: String,
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", &self.host])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.namespace])
            .status();
    }
}

fn run(program: &str, args: &[&str]) -> Output {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn tc_filters(interface: &str, direction: &str) -> String {
    String::from_utf8(run("tc", &["filter", "show", "dev", interface, direction]).stdout).unwrap()
}

fn map_bytes(adapter: &mut SystemAyaAdapter) -> u64 {
    adapter
        .read_clients()
        .unwrap()
        .entries
        .iter()
        .map(|entry| entry.counters.bytes)
        .sum()
}

fn object_paths() -> (PathBuf, PathBuf) {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    let output = workspace.join("target/bpfel-unknown-none/release");
    (
        output.join("lanspeed-ebpf-kfunc"),
        output.join("lanspeed-ebpf-fallback"),
    )
}

fn load_runtime(
    adapter: &mut SystemAyaAdapter,
) -> BpfRuntime<lanspeedd::collectors::bpf::runtime::SystemAyaLink> {
    let (primary, fallback) = object_paths();
    assert!(primary.is_file(), "missing {}", primary.display());
    assert!(fallback.is_file(), "missing {}", fallback.display());
    BpfRuntime::load(adapter, primary, fallback).unwrap()
}

fn ping(namespace: &str, address: &str) {
    run(
        "ip",
        &[
            "netns", "exec", namespace, "ping", "-c", "3", "-W", "1", address,
        ],
    );
}

#[test]
#[ignore = "requires root, iproute2, ping, and freshly built eBPF objects"]
fn real_veth_mode_switch_suspends_and_resumes_the_same_object() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "host smoke requires root");
    let suffix = std::process::id() % 100_000;
    let host = format!("ls{suffix}h");
    let peer = format!("ls{suffix}p");
    let namespace = format!("ls-mode-{suffix}");
    let octet = 20 + suffix % 200;
    let host_address = format!("198.18.{octet}.1");
    let peer_address = format!("198.18.{octet}.2");

    run("ip", &["netns", "add", &namespace]);
    let network = TestNetwork {
        host: host.clone(),
        namespace: namespace.clone(),
    };
    run(
        "ip",
        &["link", "add", &host, "type", "veth", "peer", "name", &peer],
    );
    run("ip", &["link", "set", &peer, "netns", &namespace]);
    run(
        "ip",
        &["addr", "add", &format!("{host_address}/24"), "dev", &host],
    );
    run("ip", &["link", "set", &host, "up"]);
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespace,
            "ip",
            "addr",
            "add",
            &format!("{peer_address}/24"),
            "dev",
            &peer,
        ],
    );
    run(
        "ip",
        &[
            "netns", "exec", &namespace, "ip", "link", "set", &peer, "up",
        ],
    );

    let mut normal_adapter = SystemAyaAdapter::new();
    let mut normal = load_runtime(&mut normal_adapter);
    normal
        .attach_interface(&mut normal_adapter, &host, AttachMode::Normal)
        .unwrap();
    ping(&namespace, &host_address);
    let normal_before_abort = map_bytes(&mut normal_adapter);
    assert!(normal_before_abort > 0);
    let suspended_normal = normal.suspend_for_replacement(&mut normal_adapter).unwrap();
    assert!(!tc_filters(&host, "ingress").contains("pref 49152"));
    normal
        .attach_suspended(
            &mut normal_adapter,
            &suspended_normal,
            std::slice::from_ref(&host),
            AttachMode::EarlyPassthrough,
        )
        .unwrap();
    ping(&namespace, &host_address);
    let early_before_abort = map_bytes(&mut normal_adapter);
    assert!(early_before_abort > 0);
    assert!(tc_filters(&host, "ingress").contains("pref 1"));
    assert!(!tc_filters(&host, "ingress").contains("pref 49152"));

    let suspended_early = normal.suspend_for_replacement(&mut normal_adapter).unwrap();
    drop(suspended_early);
    normal
        .resume_suspended(&mut normal_adapter, suspended_normal)
        .unwrap();
    let ingress = tc_filters(&host, "ingress");
    assert!(!ingress.contains("pref 1"));
    assert!(ingress.contains("pref 49152"));
    ping(&namespace, &host_address);
    assert!(map_bytes(&mut normal_adapter) > normal_before_abort);
    normal.shutdown(&mut normal_adapter).unwrap();

    let mut old_early_adapter = SystemAyaAdapter::new();
    let mut old_early = load_runtime(&mut old_early_adapter);
    old_early
        .attach_interface(&mut old_early_adapter, &host, AttachMode::EarlyPassthrough)
        .unwrap();
    ping(&namespace, &host_address);
    assert!(map_bytes(&mut old_early_adapter) > 0);
    let suspended_early = old_early
        .suspend_for_replacement(&mut old_early_adapter)
        .unwrap();
    assert!(!tc_filters(&host, "ingress").contains("pref 1"));
    old_early
        .attach_suspended(
            &mut old_early_adapter,
            &suspended_early,
            std::slice::from_ref(&host),
            AttachMode::Normal,
        )
        .unwrap();
    ping(&namespace, &host_address);
    let candidate_before_commit = map_bytes(&mut old_early_adapter);
    assert!(candidate_before_commit > 0);

    drop(suspended_early);
    let ingress = tc_filters(&host, "ingress");
    assert!(!ingress.contains("pref 1"));
    assert!(ingress.contains("pref 49152"));
    ping(&namespace, &host_address);
    assert!(map_bytes(&mut old_early_adapter) > candidate_before_commit);
    old_early.shutdown(&mut old_early_adapter).unwrap();
    assert!(!tc_filters(&host, "ingress").contains("pref "));

    drop(network);
}
