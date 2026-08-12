use crate::control::ControlPlan;

use super::{classifier, cpu_path, shaper};

pub(super) fn quiesce(plan: &ControlPlan) -> Result<(), String> {
    safe_preserve_direct_shaper(
        || classifier::quiesce(plan),
        || cpu_path::quiesce(plan),
        || classifier::refresh_connections(plan),
        shaper::passthrough,
    )
}

pub(super) fn deactivate(plan: &ControlPlan) -> Result<(), String> {
    safe_preserve_direct_shaper(
        classifier::cleanup,
        cpu_path::cleanup,
        || classifier::refresh_connections(plan),
        shaper::passthrough,
    )
}

pub(super) fn cleanup(plan: &ControlPlan) -> Result<(), String> {
    let remove_direct = direct_cleanup_proven(plan);
    safe_remove_direct_shaper(
        classifier::cleanup,
        cpu_path::cleanup,
        || classifier::refresh_connections(plan),
        shaper::cleanup,
        remove_direct,
    )
}

fn direct_cleanup_proven(plan: &ControlPlan) -> Result<bool, String> {
    Ok(!shaper::owned_tree_present()? || classifier::has_conntrack_identities(plan))
}

fn safe_preserve_direct_shaper(
    classifier_cleanup: impl FnOnce() -> Result<(), String>,
    cpu_cleanup: impl FnOnce() -> Result<(), String>,
    refresh_connections: impl FnOnce() -> Result<(), String>,
    shaper_passthrough: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let classifier_result = classifier_cleanup();
    let cpu_result = cpu_cleanup();
    let refresh_result = refresh_connections();
    let shaper_result = if classifier_result.is_ok() && refresh_result.is_ok() {
        shaper_passthrough()
    } else {
        Ok(())
    };
    finish_cleanup_errors(
        [classifier_result, cpu_result, refresh_result, shaper_result]
            .into_iter()
            .filter_map(Result::err),
    )
}

fn safe_remove_direct_shaper(
    classifier_cleanup: impl FnOnce() -> Result<(), String>,
    cpu_cleanup: impl FnOnce() -> Result<(), String>,
    refresh_connections: impl FnOnce() -> Result<(), String>,
    shaper_cleanup: impl FnOnce() -> Result<(), String>,
    remove_direct: Result<bool, String>,
) -> Result<(), String> {
    let (remove_direct, direct_inspection_error) = match remove_direct {
        Ok(remove) => (remove, None),
        Err(error) => (false, Some(error)),
    };
    let classifier_result = classifier_cleanup();
    let cpu_result = cpu_cleanup();
    let refresh_result = refresh_connections();
    let shaper_result = if remove_direct && classifier_result.is_ok() && refresh_result.is_ok() {
        shaper_cleanup()
    } else {
        Ok(())
    };
    finish_cleanup_errors(
        direct_inspection_error.into_iter().chain(
            [classifier_result, cpu_result, refresh_result, shaper_result]
                .into_iter()
                .filter_map(Result::err),
        ),
    )
}

fn finish_cleanup_errors(errors: impl IntoIterator<Item = String>) -> Result<(), String> {
    let errors = errors.into_iter().collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    #[test]
    fn rollback_attempts_independent_cleanup_but_keeps_direct_queue_on_tag_risk() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let classifier_calls = Rc::clone(&calls);
        let cpu_calls = Rc::clone(&calls);
        let refresh_calls = Rc::clone(&calls);
        let shaper_calls = Rc::clone(&calls);
        let result = safe_remove_direct_shaper(
            move || {
                classifier_calls.borrow_mut().push("classifier");
                Err("classifier_cleanup_failed".into())
            },
            move || {
                cpu_calls.borrow_mut().push("cpu");
                Ok(())
            },
            move || {
                refresh_calls.borrow_mut().push("conntrack");
                Err("conntrack_cleanup_failed".into())
            },
            move || {
                shaper_calls.borrow_mut().push("shaper");
                Ok(())
            },
            Ok(true),
        );

        assert_eq!(
            result.unwrap_err(),
            "classifier_cleanup_failed;conntrack_cleanup_failed"
        );
        assert_eq!(&*calls.borrow(), &["classifier", "cpu", "conntrack"]);
    }

    #[test]
    fn direct_queue_is_removed_only_after_mapping_and_tag_cleanup() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let result = safe_remove_direct_shaper(
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("classifier");
                    Ok(())
                }
            },
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("cpu");
                    Ok(())
                }
            },
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("conntrack");
                    Ok(())
                }
            },
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("shaper");
                    Ok(())
                }
            },
            Ok(true),
        );

        assert!(result.is_ok());
        assert_eq!(
            &*calls.borrow(),
            &["classifier", "cpu", "conntrack", "shaper"]
        );
    }

    #[test]
    fn direct_queue_is_preserved_without_a_proven_conntrack_identity() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let shaper_calls = Rc::clone(&calls);
        let result = safe_remove_direct_shaper(
            || Ok(()),
            || Ok(()),
            || Ok(()),
            move || {
                shaper_calls.borrow_mut().push("shaper");
                Ok(())
            },
            Ok(false),
        );
        assert!(result.is_ok());
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn runtime_quiesce_keeps_the_physical_root_as_passthrough() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let result = safe_preserve_direct_shaper(
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("classifier");
                    Ok(())
                }
            },
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("cpu");
                    Ok(())
                }
            },
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("conntrack");
                    Ok(())
                }
            },
            {
                let calls = Rc::clone(&calls);
                move || {
                    calls.borrow_mut().push("passthrough");
                    Ok(())
                }
            },
        );

        assert!(result.is_ok());
        assert_eq!(
            &*calls.borrow(),
            &["classifier", "cpu", "conntrack", "passthrough"]
        );
    }
}
