use super::system;

const TABLE: &str = "lanspeed_nss_control";
const OWNER_COMMENT: &str = "lanspeedd:nss-client-control:v1";

/// Remove only the v1 table left by the withdrawn NSS control experiment.
/// The current transactional classifier owns a v2 marker and is never matched
/// by this migration.
pub(super) fn cleanup() -> Result<(), String> {
    let output = match system::output("nft", &["list", "table", "inet", TABLE]) {
        Ok(output) => output,
        Err(error) if error == "nft_unavailable" => return Ok(()),
        Err(_) => return Err("nss_legacy_cleanup_failed".into()),
    };
    if !output.status.success() {
        return Ok(());
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    if !owned(&listing) {
        return Ok(());
    }
    system::run("nft", &["delete", "table", "inet", TABLE])
        .map_err(|_| "nss_legacy_cleanup_failed".into())
}

fn owned(listing: &str) -> bool {
    listing.contains(&format!("table inet {TABLE}"))
        && listing.contains(&format!("comment \"{OWNER_COMMENT}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_requires_the_exact_legacy_owner_marker() {
        assert!(owned(
            "table inet lanspeed_nss_control { comment \"lanspeedd:nss-client-control:v1\"; }"
        ));
        assert!(!owned("table inet lanspeed_nss_control { }"));
        assert!(!owned(
            "table inet somebody_else { comment \"lanspeedd:nss-client-control:v1\"; }"
        ));
    }
}
