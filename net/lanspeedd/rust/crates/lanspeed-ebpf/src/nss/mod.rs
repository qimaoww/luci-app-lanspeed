//! Qualcomm NSS TC/ECM implementation.
//!
//! NSS has a separate map namespace and callback surface.  Keeping the
//! module boundary explicit prevents the x86 object from accidentally
//! acquiring NSS probes or maps when features change.

#[cfg(feature = "nss-tc")]
mod account;
#[cfg(all(feature = "nss-tc", feature = "conntrack-kfunc"))]
mod conntrack;

#[cfg(feature = "nss-ecm")]
mod ecm;

#[cfg(feature = "nss-ecm")]
pub use ecm::{lanspeed_ecm_nss_enter, lanspeed_ecm_nss_exit, lanspeed_ecm_update};

#[cfg(feature = "nss-tc")]
pub(crate) use account::account_frame;
