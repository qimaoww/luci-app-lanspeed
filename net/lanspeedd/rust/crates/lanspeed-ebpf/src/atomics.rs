//! BPF targets expose atomic load/store but not the regular Rust atomic RMW
//! operations. Keep the intrinsic spelling compatible with each stable API.

#[rustversion::before(1.89)]
#[cfg(feature = "conntrack-kfunc")]
#[inline(always)]
pub unsafe fn add_u32(ptr: *mut u32, value: u32) {
    unsafe { core::intrinsics::atomic_xadd_relaxed(ptr, value) };
}

#[rustversion::before(1.89)]
#[inline(always)]
pub unsafe fn add_u64(ptr: *mut u64, value: u64) {
    unsafe { core::intrinsics::atomic_xadd_relaxed(ptr, value) };
}

#[rustversion::since(1.89)]
#[rustversion::before(1.91)]
#[cfg(feature = "conntrack-kfunc")]
#[inline(always)]
pub unsafe fn add_u32(ptr: *mut u32, value: u32) {
    unsafe {
        core::intrinsics::atomic_xadd::<_, { core::intrinsics::AtomicOrdering::Relaxed }>(
            ptr, value,
        )
    };
}

#[rustversion::since(1.89)]
#[rustversion::before(1.91)]
#[inline(always)]
pub unsafe fn add_u64(ptr: *mut u64, value: u64) {
    unsafe {
        core::intrinsics::atomic_xadd::<_, { core::intrinsics::AtomicOrdering::Relaxed }>(
            ptr, value,
        )
    };
}

#[rustversion::since(1.91)]
#[cfg(feature = "conntrack-kfunc")]
#[inline(always)]
pub unsafe fn add_u32(ptr: *mut u32, value: u32) {
    unsafe {
        core::intrinsics::atomic_xadd::<_, _, { core::intrinsics::AtomicOrdering::Relaxed }>(
            ptr, value,
        )
    };
}

#[rustversion::since(1.91)]
#[inline(always)]
pub unsafe fn add_u64(ptr: *mut u64, value: u64) {
    unsafe {
        core::intrinsics::atomic_xadd::<_, _, { core::intrinsics::AtomicOrdering::Relaxed }>(
            ptr, value,
        )
    };
}
