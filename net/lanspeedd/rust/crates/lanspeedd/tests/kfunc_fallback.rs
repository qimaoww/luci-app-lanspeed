use std::cell::Cell;

use lanspeedd::{is_known_kfunc_metadata_incompatibility, load_with_fallback, KfuncPatchError};

#[test]
fn recognizes_only_the_router_kfunc_metadata_mismatch() {
    let known = "release kernel function bpf_skb_ct_lookup expects refcounted PTR_TO_BTF_ID";
    assert!(is_known_kfunc_metadata_incompatibility(known));

    assert!(!is_known_kfunc_metadata_incompatibility(
        "release kernel function bpf_ct_release expects refcounted PTR_TO_BTF_ID"
    ));
    assert!(!is_known_kfunc_metadata_incompatibility(
        "arg#0 expected pointer to ctx, but got fp"
    ));
    assert!(!is_known_kfunc_metadata_incompatibility(
        "cannot call kernel function from non-GPL compatible program"
    ));
}

#[test]
fn retries_once_only_for_a_known_primary_error() {
    let primary_calls = Cell::new(0);
    let fallback_calls = Cell::new(0);
    let loaded = load_with_fallback(
        || {
            primary_calls.set(primary_calls.get() + 1);
            Err::<u8, _>("known")
        },
        || {
            fallback_calls.set(fallback_calls.get() + 1);
            Ok(7)
        },
        |error| *error == "known",
    )
    .unwrap();

    assert_eq!(loaded.value, 7);
    assert_eq!(loaded.primary_error, Some("known"));
    assert_eq!(primary_calls.get(), 1);
    assert_eq!(fallback_calls.get(), 1);
}

#[test]
fn never_loads_fallback_after_success_or_an_unknown_error() {
    let fallback_calls = Cell::new(0);
    let loaded = load_with_fallback(
        || Ok::<_, &str>(3),
        || {
            fallback_calls.set(fallback_calls.get() + 1);
            Ok(9)
        },
        |_| false,
    )
    .unwrap();
    assert_eq!(loaded.value, 3);
    assert_eq!(loaded.primary_error, None);

    let error = load_with_fallback(
        || Err::<u8, _>("unknown"),
        || {
            fallback_calls.set(fallback_calls.get() + 1);
            Ok(9)
        },
        |_| false,
    )
    .unwrap_err();
    assert_eq!(error, "unknown");
    assert_eq!(fallback_calls.get(), 0);
}

#[test]
fn kernel_btf_preflight_errors_retry_fallback_once() {
    let fallback_calls = Cell::new(0);
    let loaded = load_with_fallback(
        || {
            Err::<u8, _>(KfuncPatchError::Resolve {
                name: "bpf_skb_ct_lookup".into(),
                reason: "not in kernel BTF".into(),
            })
        },
        || {
            fallback_calls.set(fallback_calls.get() + 1);
            Ok(11)
        },
        KfuncPatchError::is_kernel_incompatibility,
    )
    .unwrap();

    assert_eq!(loaded.value, 11);
    assert!(matches!(
        loaded.primary_error,
        Some(KfuncPatchError::Resolve { .. })
    ));
    assert_eq!(fallback_calls.get(), 1);
}

#[test]
fn malformed_application_elf_does_not_enter_fallback() {
    for error in [
        KfuncPatchError::MissingRelocation("bpf_ct_release".into()),
        KfuncPatchError::InvalidInstruction("bpf_skb_ct_lookup".into()),
    ] {
        assert!(!error.is_kernel_incompatibility());
    }

    for error in [
        KfuncPatchError::InvalidBtf("missing module BTF".into()),
        KfuncPatchError::Io(std::io::Error::from_raw_os_error(libc::ENOENT)),
        KfuncPatchError::Io(std::io::Error::from_raw_os_error(libc::ENOSYS)),
        KfuncPatchError::Io(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
    ] {
        assert!(error.is_kernel_incompatibility());
    }

    for errno in [libc::EACCES, libc::EMFILE, libc::EIO] {
        let error = KfuncPatchError::Io(std::io::Error::from_raw_os_error(errno));
        assert!(!error.is_kernel_incompatibility());
    }
}

#[test]
fn resource_and_permission_errors_do_not_attempt_fallback() {
    for errno in [libc::EACCES, libc::EMFILE, libc::EIO] {
        let fallback_calls = Cell::new(0);
        let error = load_with_fallback(
            || {
                Err::<u8, _>(KfuncPatchError::Io(std::io::Error::from_raw_os_error(
                    errno,
                )))
            },
            || {
                fallback_calls.set(fallback_calls.get() + 1);
                Ok(11)
            },
            KfuncPatchError::is_kernel_incompatibility,
        )
        .unwrap_err();

        assert!(matches!(error, KfuncPatchError::Io(_)));
        assert_eq!(fallback_calls.get(), 0);
    }
}
