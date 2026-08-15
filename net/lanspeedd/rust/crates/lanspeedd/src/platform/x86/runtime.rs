//! x86 TC-BPF backend boundary.
//!
//! The implementation lives in the platform-neutral TC-BPF adapter. Keeping
//! this wrapper preserves the x86 backend API without making NSS import x86
//! data-plane code.

pub use crate::platform::tc_bpf_runtime::*;
