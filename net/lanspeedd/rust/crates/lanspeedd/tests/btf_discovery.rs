use std::{fs::File, io, os::fd::AsRawFd};

use lanspeedd::{select_kernel_btf_candidate, KernelBtfCandidate};

fn candidate(name: &str, kernel_btf: bool) -> KernelBtfCandidate {
    KernelBtfCandidate {
        fd: File::open("/dev/null").unwrap().into(),
        kernel_btf,
        name: name.to_owned(),
    }
}

#[test]
fn filters_kernel_module_btf_by_flag_and_name() {
    assert!(
        select_kernel_btf_candidate("nf_conntrack", Ok(candidate("nf_conntrack", false)))
            .unwrap()
            .is_none()
    );
    assert!(
        select_kernel_btf_candidate("nf_conntrack", Ok(candidate("nf_nat", true)))
            .unwrap()
            .is_none()
    );
}

#[test]
fn skips_enoent_unload_race_and_returns_owned_matching_fd() {
    assert!(select_kernel_btf_candidate(
        "nf_conntrack",
        Err(io::Error::from_raw_os_error(libc::ENOENT)),
    )
    .unwrap()
    .is_none());

    let selected = select_kernel_btf_candidate("nf_conntrack", Ok(candidate("nf_conntrack", true)))
        .unwrap()
        .unwrap();
    assert!(selected.as_raw_fd() >= 0);
}
