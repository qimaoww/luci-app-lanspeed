use crate::{raw, Error, Result};
use std::ffi::CString;
use std::marker::PhantomData;
use std::rc::Rc;

#[derive(Clone, Copy)]
struct BlobOps {
    init: unsafe extern "C" fn(*mut raw::blob_buf, libc::c_int) -> libc::c_int,
    free: unsafe extern "C" fn(*mut raw::blob_buf),
    add_json: unsafe extern "C" fn(*mut raw::blob_buf, *const libc::c_char) -> bool,
}

const REAL_OPS: BlobOps = BlobOps {
    init: raw::blob_buf_init,
    free: raw::blob_buf_free,
    add_json: raw::blobmsg_add_json_from_string,
};

pub struct BlobBuf {
    raw: raw::blob_buf,
    ops: BlobOps,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl BlobBuf {
    pub fn from_json(json: &str) -> Result<Self> {
        Self::from_json_with(json, REAL_OPS)
    }

    fn from_json_with(json: &str, ops: BlobOps) -> Result<Self> {
        let json = CString::new(json)?;
        let mut value = Self {
            raw: raw::blob_buf::default(),
            ops,
            _not_send_or_sync: PhantomData,
        };
        let result = unsafe { (value.ops.init)(&mut value.raw, 0) };
        if result != 0 {
            return Err(Error::Platform {
                operation: "blob_buf_init",
                code: result,
            });
        }
        if !unsafe { (value.ops.add_json)(&mut value.raw, json.as_ptr()) } {
            return Err(Error::InvalidJson);
        }
        Ok(value)
    }

    pub(crate) fn head(&self) -> *mut raw::blob_attr {
        self.raw.head
    }
}

impl Drop for BlobBuf {
    fn drop(&mut self) {
        unsafe { (self.ops.free)(&mut self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn init(_buf: *mut crate::raw::blob_buf, _id: libc::c_int) -> libc::c_int {
        INIT_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn free(_buf: *mut crate::raw::blob_buf) {
        FREE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn accept_json(
        _buf: *mut crate::raw::blob_buf,
        _json: *const libc::c_char,
    ) -> bool {
        true
    }

    unsafe extern "C" fn reject_json(
        _buf: *mut crate::raw::blob_buf,
        _json: *const libc::c_char,
    ) -> bool {
        false
    }

    fn reset() {
        INIT_CALLS.store(0, Ordering::SeqCst);
        FREE_CALLS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn from_json_frees_owned_buffer_on_drop() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset();
        let value = BlobBuf::from_json_with(
            r#"{"ok":true}"#,
            BlobOps {
                init,
                free,
                add_json: accept_json,
            },
        )
        .unwrap();

        assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 0);
        drop(value);
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn from_json_frees_initialized_buffer_when_json_is_rejected() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset();
        let result = BlobBuf::from_json_with(
            "not-json",
            BlobOps {
                init,
                free,
                add_json: reject_json,
            },
        );

        assert!(result.is_err());
        assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
    }
}
