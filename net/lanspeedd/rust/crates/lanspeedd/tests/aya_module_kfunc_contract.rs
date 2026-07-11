use std::{fs, path::PathBuf};

#[test]
fn aya_program_load_owns_and_propagates_module_btf_fds() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let loader = fs::read_to_string(root.join("vendor/aya/src/bpf.rs")).unwrap();
    let programs = fs::read_to_string(root.join("vendor/aya/src/programs/mod.rs")).unwrap();
    let syscall = fs::read_to_string(root.join("vendor/aya/src/sys/bpf.rs")).unwrap();

    assert!(loader.contains("pub fn kfunc_btf_fds"));
    assert!(loader.contains("Arc<[crate::MockableFd]>"));
    assert!(programs.contains("kfunc_btf_fds: Arc<[crate::MockableFd]>,"));
    assert!(syscall.contains("let kfunc_fd_array = std::iter::once(0)"));
    assert!(syscall.contains("u.fd_array = kfunc_fd_array.as_ptr() as u64"));
}
