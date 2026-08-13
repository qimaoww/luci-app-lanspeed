//! x86_64 TC-BPF implementation.
//!
//! This module is the only entry point for the x86 accounting object. Other
//! platform programs live behind their own feature-gated module boundary and
//! are never pulled into an x86 build.

mod accounting;

#[cfg(feature = "conntrack-kfunc")]
mod connections;

pub(crate) use accounting::account_frame;
