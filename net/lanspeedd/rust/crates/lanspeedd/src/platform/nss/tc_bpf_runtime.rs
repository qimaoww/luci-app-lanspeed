//! NSS TC-BPF slow-path backend boundary.
//!
//! NSS uses its own ECM/NSS data plane; this adapter is limited to the
//! architecture-specific TC-BPF slow path and is not the x86 backend.

pub(crate) use crate::platform::tc_bpf_runtime::*;
