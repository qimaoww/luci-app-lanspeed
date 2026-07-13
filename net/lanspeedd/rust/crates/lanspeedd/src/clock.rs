use std::{io, mem::MaybeUninit};

pub(crate) fn monotonic_millis() -> io::Result<u64> {
    let mut value = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes the pointed-to timespec on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful clock_gettime call initialized every timespec field.
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative monotonic seconds"))?;
    let nanoseconds = u64::try_from(value.tv_nsec).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "negative monotonic nanoseconds")
    })?;
    if nanoseconds >= 1_000_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "monotonic nanoseconds out of range",
        ));
    }
    seconds
        .checked_mul(1_000)
        .and_then(|millis| millis.checked_add(nanoseconds / 1_000_000))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "monotonic time overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_monotonic_millis() -> u64 {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: this test passes a valid output pointer and asserts syscall success.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) },
            0
        );
        // SAFETY: the successful clock_gettime call initialized the value.
        let value = unsafe { value.assume_init() };
        u64::try_from(value.tv_sec).unwrap() * 1_000
            + u64::try_from(value.tv_nsec).unwrap() / 1_000_000
    }

    #[test]
    fn milliseconds_use_the_system_boot_monotonic_epoch() {
        let before = direct_monotonic_millis();
        let observed = monotonic_millis().unwrap();
        let after = direct_monotonic_millis();

        assert!(observed >= before);
        assert!(observed <= after);
    }
}
