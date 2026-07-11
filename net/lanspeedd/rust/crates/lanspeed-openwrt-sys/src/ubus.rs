use crate::{raw, BlobBuf, Error, Result};
use std::ffi::{CStr, CString};
use std::marker::{PhantomData, PhantomPinned};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::ptr;
use std::rc::Rc;

pub const STATUS_OK: libc::c_int = raw::ubus_msg_status_UBUS_STATUS_OK.0 as libc::c_int;
pub const STATUS_UNKNOWN_ERROR: libc::c_int =
    raw::ubus_msg_status_UBUS_STATUS_UNKNOWN_ERROR.0 as libc::c_int;

type Handler = dyn for<'request> FnMut(UbusRequest<'request>) -> libc::c_int;

#[derive(Clone, Copy)]
struct UbusOps {
    connect: unsafe extern "C" fn(*const libc::c_char) -> *mut raw::ubus_context,
    free: unsafe extern "C" fn(*mut raw::ubus_context),
    add_object: unsafe extern "C" fn(*mut raw::ubus_context, *mut raw::ubus_object) -> libc::c_int,
    remove_object:
        unsafe extern "C" fn(*mut raw::ubus_context, *mut raw::ubus_object) -> libc::c_int,
    send_reply: unsafe extern "C" fn(
        *mut raw::ubus_context,
        *mut raw::ubus_request_data,
        *mut raw::blob_attr,
    ) -> libc::c_int,
}

const REAL_OPS: UbusOps = UbusOps {
    connect: raw::ubus_connect,
    free: raw::ubus_free,
    add_object: raw::ubus_add_object,
    remove_object: raw::ubus_remove_object,
    send_reply: raw::ubus_send_reply,
};

pub struct UbusMethod {
    name: CString,
    handler: Box<Handler>,
}

impl UbusMethod {
    pub fn new(
        name: &str,
        handler: impl for<'request> FnMut(UbusRequest<'request>) -> libc::c_int + 'static,
    ) -> Result<Self> {
        Ok(Self {
            name: CString::new(name)?,
            handler: Box::new(handler),
        })
    }
}

pub struct UbusRequest<'request> {
    context: *mut raw::ubus_context,
    request: *mut raw::ubus_request_data,
    ops: UbusOps,
    _lifetime: PhantomData<&'request mut raw::ubus_request_data>,
}

impl UbusRequest<'_> {
    pub fn reply_json(&mut self, json: &str) -> Result<()> {
        let message = BlobBuf::from_json(json)?;
        let result = unsafe { (self.ops.send_reply)(self.context, self.request, message.head()) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Platform {
                operation: "ubus_send_reply",
                code: result,
            })
        }
    }
}

#[repr(C)]
pub struct UbusObject {
    raw: raw::ubus_object,
    object_type: raw::ubus_object_type,
    name: CString,
    methods: Vec<UbusMethod>,
    raw_methods: Vec<raw::ubus_method>,
    ops: UbusOps,
    _not_send_or_sync: PhantomData<Rc<()>>,
    _pinned: PhantomPinned,
}

impl UbusObject {
    pub fn new(name: &str, methods: Vec<UbusMethod>) -> Result<Pin<Box<Self>>> {
        let name = CString::new(name)?;
        let method_count = libc::c_int::try_from(methods.len())
            .map_err(|_| Error::InvalidData("too many ubus methods"))?;
        let raw_methods = methods
            .iter()
            .map(|method| raw::ubus_method {
                name: method.name.as_ptr(),
                handler: Some(method_trampoline),
                mask: 0,
                tags: 0,
                policy: ptr::null(),
                n_policy: 0,
            })
            .collect();
        let mut object = Box::pin(Self {
            raw: raw::ubus_object::default(),
            object_type: raw::ubus_object_type::default(),
            name,
            methods,
            raw_methods,
            ops: REAL_OPS,
            _not_send_or_sync: PhantomData,
            _pinned: PhantomPinned,
        });
        let this = unsafe { object.as_mut().get_unchecked_mut() };
        this.object_type.name = this.name.as_ptr();
        this.object_type.methods = this.raw_methods.as_ptr();
        this.object_type.n_methods = method_count;
        this.raw.name = this.name.as_ptr();
        this.raw.type_ = &mut this.object_type;
        this.raw.methods = this.raw_methods.as_ptr();
        this.raw.n_methods = method_count;
        Ok(object)
    }

    fn raw_mut(self: Pin<&mut Self>) -> *mut raw::ubus_object {
        let this = unsafe { self.get_unchecked_mut() };
        &mut this.raw
    }

    #[cfg(test)]
    fn raw_ptr(self: Pin<&Self>) -> *const raw::ubus_object {
        &self.get_ref().raw
    }

    #[cfg(test)]
    fn methods_ptr(self: Pin<&Self>) -> *const raw::ubus_method {
        self.get_ref().raw_methods.as_ptr()
    }

    #[cfg(test)]
    fn invoke_for_test(
        self: Pin<&Self>,
        method: *const libc::c_char,
        request: *mut raw::ubus_request_data,
        _ops: UbusOps,
    ) -> libc::c_int {
        let object = self.raw_ptr().cast_mut();
        unsafe { method_trampoline(ptr::null_mut(), object, request, method, ptr::null_mut()) }
    }
}

unsafe extern "C" fn method_trampoline(
    context: *mut raw::ubus_context,
    object: *mut raw::ubus_object,
    request: *mut raw::ubus_request_data,
    method: *const libc::c_char,
    _message: *mut raw::blob_attr,
) -> libc::c_int {
    if object.is_null() || request.is_null() || method.is_null() {
        return STATUS_UNKNOWN_ERROR;
    }
    let object = unsafe { &mut *object.cast::<UbusObject>() };
    let method_name = unsafe { CStr::from_ptr(method) }.to_bytes();
    let Some(method) = object
        .methods
        .iter_mut()
        .find(|candidate| candidate.name.as_bytes() == method_name)
    else {
        return STATUS_UNKNOWN_ERROR;
    };
    let ubus_request = UbusRequest {
        context,
        request,
        ops: object.ops,
        _lifetime: PhantomData,
    };
    catch_unwind(AssertUnwindSafe(|| (method.handler)(ubus_request)))
        .unwrap_or(STATUS_UNKNOWN_ERROR)
}

pub struct UbusConnection {
    context: *mut raw::ubus_context,
    objects: Vec<Pin<Box<UbusObject>>>,
    ops: UbusOps,
    attached_to_uloop: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl UbusConnection {
    pub fn connect(path: Option<&str>) -> Result<Self> {
        Self::connect_with(path, REAL_OPS)
    }

    fn connect_with(path: Option<&str>, ops: UbusOps) -> Result<Self> {
        let path = path.map(CString::new).transpose()?;
        let path_pointer = path.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let context = unsafe { (ops.connect)(path_pointer) };
        if context.is_null() {
            return Err(Error::Allocation("ubus context"));
        }
        Ok(Self {
            context,
            objects: Vec::new(),
            ops,
            attached_to_uloop: false,
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn attach_uloop(&mut self) -> Result<()> {
        if self.attached_to_uloop {
            return Ok(());
        }
        let socket = unsafe { &mut (*self.context).sock };
        let flags = raw::ULOOP_READ | raw::ULOOP_BLOCKING;
        let result = unsafe { raw::uloop_fd_add(socket, flags) };
        if result != 0 {
            return Err(Error::Platform {
                operation: "uloop_fd_add",
                code: result,
            });
        }
        self.attached_to_uloop = true;
        Ok(())
    }

    pub fn reconnect(&mut self, path: Option<&str>) -> Result<()> {
        let path = path.map(CString::new).transpose()?;
        let path_pointer = path.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let result = unsafe { raw::ubus_reconnect(self.context, path_pointer) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Platform {
                operation: "ubus_reconnect",
                code: result,
            })
        }
    }

    pub fn lookup_id(&mut self, path: &str) -> Result<u32> {
        let path = CString::new(path)?;
        let mut id = 0;
        let result = unsafe { raw::ubus_lookup_id(self.context, path.as_ptr(), &mut id) };
        if result == 0 {
            Ok(id)
        } else {
            Err(Error::Platform {
                operation: "ubus_lookup_id",
                code: result,
            })
        }
    }

    pub fn register_object(&mut self, mut object: Pin<Box<UbusObject>>) -> Result<()> {
        unsafe { object.as_mut().get_unchecked_mut().ops = self.ops };
        let result = unsafe { (self.ops.add_object)(self.context, object.as_mut().raw_mut()) };
        if result != 0 {
            return Err(Error::Platform {
                operation: "ubus_add_object",
                code: result,
            });
        }
        self.objects.push(object);
        Ok(())
    }

    #[cfg(test)]
    fn object_ptr_for_test(&self, index: usize) -> *const raw::ubus_object {
        self.objects[index].as_ref().raw_ptr()
    }

    #[cfg(test)]
    fn methods_ptr_for_test(&self, index: usize) -> *const raw::ubus_method {
        self.objects[index].as_ref().methods_ptr()
    }

    #[cfg(test)]
    fn invoke_for_test(
        &mut self,
        index: usize,
        method: *const libc::c_char,
        request: *mut raw::ubus_request_data,
    ) -> libc::c_int {
        let object = self.objects[index].as_mut().raw_mut();
        unsafe { method_trampoline(self.context, object, request, method, ptr::null_mut()) }
    }
}

impl Drop for UbusConnection {
    fn drop(&mut self) {
        for object in &mut self.objects {
            let _ = unsafe { (self.ops.remove_object)(self.context, object.as_mut().raw_mut()) };
        }
        self.objects.clear();
        if self.attached_to_uloop {
            let socket = unsafe { &mut (*self.context).sock };
            let _ = unsafe { raw::uloop_fd_delete(socket) };
        }
        unsafe { (self.ops.free)(self.context) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::ffi::CString;
    use std::rc::Rc;
    use std::sync::Mutex;

    static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    unsafe extern "C" fn connect(_path: *const libc::c_char) -> *mut crate::raw::ubus_context {
        EVENTS.lock().unwrap().push("connect");
        Box::into_raw(Box::new(crate::raw::ubus_context::default()))
    }

    unsafe extern "C" fn free(context: *mut crate::raw::ubus_context) {
        EVENTS.lock().unwrap().push("free");
        drop(unsafe { Box::from_raw(context) });
    }

    unsafe extern "C" fn add_object(
        _context: *mut crate::raw::ubus_context,
        _object: *mut crate::raw::ubus_object,
    ) -> libc::c_int {
        EVENTS.lock().unwrap().push("add");
        0
    }

    unsafe extern "C" fn remove_object(
        _context: *mut crate::raw::ubus_context,
        _object: *mut crate::raw::ubus_object,
    ) -> libc::c_int {
        EVENTS.lock().unwrap().push("remove");
        0
    }

    unsafe extern "C" fn send_reply(
        _context: *mut crate::raw::ubus_context,
        _request: *mut crate::raw::ubus_request_data,
        _message: *mut crate::raw::blob_attr,
    ) -> libc::c_int {
        0
    }

    fn fake_ops() -> UbusOps {
        UbusOps {
            connect,
            free,
            add_object,
            remove_object,
            send_reply,
        }
    }

    struct DropProbe(Rc<Cell<usize>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn connection_owns_stable_object_method_and_callback_storage() {
        EVENTS.lock().unwrap().clear();
        let calls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));
        let callback_calls = Rc::clone(&calls);
        let probe = DropProbe(Rc::clone(&drops));
        let method = UbusMethod::new("status", move |_request| {
            let _keep_alive = &probe;
            callback_calls.set(callback_calls.get() + 1);
            STATUS_OK
        })
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let object_pointer = UbusObject::raw_ptr(object.as_ref());
        let methods_pointer = UbusObject::methods_ptr(object.as_ref());
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();

        connection.register_object(object).unwrap();

        assert_eq!(connection.object_ptr_for_test(0), object_pointer);
        assert_eq!(connection.methods_ptr_for_test(0), methods_pointer);
        let method_name = CString::new("status").unwrap();
        let mut request = crate::raw::ubus_request_data::default();
        assert_eq!(
            connection.invoke_for_test(0, method_name.as_ptr(), &mut request),
            STATUS_OK
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(drops.get(), 0);

        drop(connection);
        assert_eq!(drops.get(), 1);
        assert_eq!(
            &*EVENTS.lock().unwrap(),
            &["connect", "add", "remove", "free"]
        );
    }

    #[test]
    fn method_callback_panic_is_caught_at_ffi_boundary() {
        let method = UbusMethod::new("panic", |_request| panic!("handler failure")).unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let method_name = CString::new("panic").unwrap();
        let mut request = crate::raw::ubus_request_data::default();

        let status = UbusObject::invoke_for_test(
            object.as_ref(),
            method_name.as_ptr(),
            &mut request,
            fake_ops(),
        );

        assert_eq!(status, STATUS_UNKNOWN_ERROR);
    }
}
