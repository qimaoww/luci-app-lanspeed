use crate::{raw, BlobBuf, Error, Result};
use std::cell::{RefCell, UnsafeCell};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::rc::{Rc, Weak};

pub const STATUS_OK: libc::c_int = raw::ubus_msg_status_UBUS_STATUS_OK.0 as libc::c_int;
pub const STATUS_UNKNOWN_ERROR: libc::c_int =
    raw::ubus_msg_status_UBUS_STATUS_UNKNOWN_ERROR.0 as libc::c_int;

type Handler = dyn for<'request> FnMut(UbusRequest<'request>) -> libc::c_int;

#[derive(Clone, Copy)]
struct UbusOps {
    connect: unsafe extern "C" fn(*const libc::c_char) -> *mut raw::ubus_context,
    reconnect: unsafe extern "C" fn(*mut raw::ubus_context, *const libc::c_char) -> libc::c_int,
    free: unsafe extern "C" fn(*mut raw::ubus_context),
    add_object: unsafe extern "C" fn(*mut raw::ubus_context, *mut raw::ubus_object) -> libc::c_int,
    remove_object:
        unsafe extern "C" fn(*mut raw::ubus_context, *mut raw::ubus_object) -> libc::c_int,
    send_reply: unsafe extern "C" fn(
        *mut raw::ubus_context,
        *mut raw::ubus_request_data,
        *mut raw::blob_attr,
    ) -> libc::c_int,
    fd_add: unsafe extern "C" fn(*mut raw::uloop_fd, libc::c_uint) -> libc::c_int,
    fd_delete: unsafe extern "C" fn(*mut raw::uloop_fd) -> libc::c_int,
    defer_cleanup: fn(Rc<ConnectionInner>),
}

thread_local! {
    static CONNECTION_REGISTRY: RefCell<HashMap<usize, Weak<ConnectionInner>>> =
        RefCell::new(HashMap::new());
    static OBJECT_REGISTRY: RefCell<HashMap<usize, Weak<ObjectInner>>> =
        RefCell::new(HashMap::new());
    static DEFERRED_CONNECTION_DROPS: RefCell<Vec<Rc<ConnectionInner>>> =
        const { RefCell::new(Vec::new()) };
    static DEFERRED_CONNECTION_TIMER: crate::Timer = crate::Timer::new(|| {
        DEFERRED_CONNECTION_DROPS.with(|connections| connections.borrow_mut().clear());
    });
}

fn defer_connection_cleanup(connection: Rc<ConnectionInner>) {
    DEFERRED_CONNECTION_DROPS.with(|connections| connections.borrow_mut().push(connection));
    // If scheduling fails, retain the connection in the queue. A leak is safer
    // than freeing a context while libubus is still unwinding its dispatch.
    DEFERRED_CONNECTION_TIMER.with(|timer| {
        let _ = timer.schedule(0);
    });
}

const REAL_OPS: UbusOps = UbusOps {
    connect: raw::ubus_connect,
    reconnect: raw::ubus_reconnect,
    free: raw::ubus_free,
    add_object: raw::ubus_add_object,
    remove_object: raw::ubus_remove_object,
    send_reply: raw::ubus_send_reply,
    fd_add: raw::uloop_fd_add,
    fd_delete: raw::uloop_fd_delete,
    defer_cleanup: defer_connection_cleanup,
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
    connection: Rc<ConnectionInner>,
    request: *mut raw::ubus_request_data,
    _lifetime: PhantomData<&'request mut raw::ubus_request_data>,
}

impl UbusRequest<'_> {
    pub fn reply_json(&mut self, json: &str) -> Result<()> {
        let message = BlobBuf::from_json(json)?;
        let result = unsafe {
            (self.connection.ops.send_reply)(self.connection.context, self.request, message.head())
        };
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

pub struct UbusObject {
    name: CString,
    methods: Vec<UbusMethod>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl UbusObject {
    pub fn new(name: &str, methods: Vec<UbusMethod>) -> Result<Self> {
        libc::c_int::try_from(methods.len())
            .map_err(|_| Error::InvalidData("too many ubus methods"))?;
        Ok(Self {
            name: CString::new(name)?,
            methods,
            _not_send_or_sync: PhantomData,
        })
    }
}

struct MethodCell {
    name: CString,
    handler: RefCell<Option<Box<Handler>>>,
}

#[repr(C)]
struct ObjectInner {
    raw: UnsafeCell<raw::ubus_object>,
    object_type: UnsafeCell<raw::ubus_object_type>,
    name: CString,
    methods: Vec<MethodCell>,
    raw_methods: Box<[raw::ubus_method]>,
    connection: Weak<ConnectionInner>,
    registered: std::cell::Cell<bool>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl ObjectInner {
    fn new(object: UbusObject, connection: Weak<ConnectionInner>) -> Rc<Self> {
        let method_count = object.methods.len() as libc::c_int;
        let methods = object
            .methods
            .into_iter()
            .map(|method| MethodCell {
                name: method.name,
                handler: RefCell::new(Some(method.handler)),
            })
            .collect::<Vec<_>>();
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
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let inner = Rc::new(Self {
            raw: UnsafeCell::new(raw::ubus_object::default()),
            object_type: UnsafeCell::new(raw::ubus_object_type::default()),
            name: object.name,
            methods,
            raw_methods,
            connection,
            registered: std::cell::Cell::new(false),
            _not_send_or_sync: PhantomData,
        });
        unsafe {
            let object_type = &mut *inner.object_type.get();
            object_type.name = inner.name.as_ptr();
            object_type.methods = inner.raw_methods.as_ptr();
            object_type.n_methods = method_count;
            let raw = &mut *inner.raw.get();
            raw.name = inner.name.as_ptr();
            raw.type_ = object_type;
            raw.methods = inner.raw_methods.as_ptr();
            raw.n_methods = method_count;
        }
        inner
    }

    fn raw_ptr(&self) -> *mut raw::ubus_object {
        self.raw.get()
    }
}

unsafe extern "C" fn method_trampoline(
    _context: *mut raw::ubus_context,
    object: *mut raw::ubus_object,
    request: *mut raw::ubus_request_data,
    method: *const libc::c_char,
    _message: *mut raw::blob_attr,
) -> libc::c_int {
    if object.is_null() || request.is_null() || method.is_null() {
        return STATUS_UNKNOWN_ERROR;
    }
    let Some(object) = OBJECT_REGISTRY.with(|registry| {
        registry
            .borrow()
            .get(&(object as usize))
            .and_then(Weak::upgrade)
    }) else {
        return STATUS_UNKNOWN_ERROR;
    };
    let Some(connection) = object.connection.upgrade() else {
        return STATUS_UNKNOWN_ERROR;
    };
    connection
        .dispatch_depth
        .set(connection.dispatch_depth.get() + 1);
    struct DispatchGuard<'a>(&'a ConnectionInner);
    impl Drop for DispatchGuard<'_> {
        fn drop(&mut self) {
            self.0.dispatch_depth.set(self.0.dispatch_depth.get() - 1);
        }
    }
    let _dispatch_guard = DispatchGuard(&connection);
    let method_name = unsafe { CStr::from_ptr(method) }.to_bytes();
    let Some(method) = object
        .methods
        .iter()
        .find(|candidate| candidate.name.as_bytes() == method_name)
    else {
        return STATUS_UNKNOWN_ERROR;
    };
    let Some(mut handler) = method.handler.borrow_mut().take() else {
        return STATUS_UNKNOWN_ERROR;
    };
    let ubus_request = UbusRequest {
        connection: Rc::clone(&connection),
        request,
        _lifetime: PhantomData,
    };
    let status =
        catch_unwind(AssertUnwindSafe(|| handler(ubus_request))).unwrap_or(STATUS_UNKNOWN_ERROR);
    *method.handler.borrow_mut() = Some(handler);
    status
}

pub struct UbusConnection {
    inner: Rc<ConnectionInner>,
}

struct ConnectionState {
    objects: Vec<Rc<ObjectInner>>,
    wants_uloop: bool,
    fd_registered: bool,
}

struct ConnectionInner {
    context: *mut raw::ubus_context,
    state: RefCell<ConnectionState>,
    ops: UbusOps,
    dispatch_depth: std::cell::Cell<usize>,
    connection_lost_handler: RefCell<Option<Box<dyn FnMut()>>>,
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
        let inner = Rc::new(ConnectionInner {
            context,
            state: RefCell::new(ConnectionState {
                objects: Vec::new(),
                wants_uloop: false,
                fd_registered: false,
            }),
            ops,
            dispatch_depth: std::cell::Cell::new(0),
            connection_lost_handler: RefCell::new(None),
            _not_send_or_sync: PhantomData,
        });
        CONNECTION_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .insert(context as usize, Rc::downgrade(&inner));
        });
        Ok(Self { inner })
    }

    pub fn attach_uloop(&mut self) -> Result<()> {
        self.inner.state.borrow_mut().wants_uloop = true;
        if self.inner.state.borrow().fd_registered {
            return Ok(());
        }
        let socket = unsafe { &mut (*self.inner.context).sock };
        let flags = raw::ULOOP_READ | raw::ULOOP_BLOCKING;
        let result = unsafe { (self.inner.ops.fd_add)(socket, flags) };
        if result != 0 {
            return Err(Error::Platform {
                operation: "uloop_fd_add",
                code: result,
            });
        }
        self.inner.state.borrow_mut().fd_registered = true;
        Ok(())
    }

    pub fn reconnect(&mut self, path: Option<&str>) -> Result<()> {
        let path = path.map(CString::new).transpose()?;
        let path_pointer = path.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let was_registered = self.inner.state.borrow().fd_registered;
        if was_registered {
            let socket = unsafe { &mut (*self.inner.context).sock };
            let result = unsafe { (self.inner.ops.fd_delete)(socket) };
            if result != 0 {
                return Err(Error::Platform {
                    operation: "uloop_fd_delete",
                    code: result,
                });
            }
            self.inner.state.borrow_mut().fd_registered = false;
        }
        let result = unsafe { (self.inner.ops.reconnect)(self.inner.context, path_pointer) };
        if result != 0 {
            return Err(Error::Platform {
                operation: "ubus_reconnect",
                code: result,
            });
        }
        if self.inner.state.borrow().wants_uloop {
            let socket = unsafe { &mut (*self.inner.context).sock };
            let flags = raw::ULOOP_READ | raw::ULOOP_BLOCKING;
            let result = unsafe { (self.inner.ops.fd_add)(socket, flags) };
            if result != 0 {
                return Err(Error::Platform {
                    operation: "uloop_fd_add",
                    code: result,
                });
            }
            self.inner.state.borrow_mut().fd_registered = true;
        }
        for object in &self.inner.state.borrow().objects {
            object.registered.set(false);
        }
        Ok(())
    }

    pub fn lookup_id(&mut self, path: &str) -> Result<u32> {
        let path = CString::new(path)?;
        let mut id = 0;
        let result = unsafe { raw::ubus_lookup_id(self.inner.context, path.as_ptr(), &mut id) };
        if result == 0 {
            Ok(id)
        } else {
            Err(Error::Platform {
                operation: "ubus_lookup_id",
                code: result,
            })
        }
    }

    pub fn register_object(&mut self, object: UbusObject) -> Result<()> {
        let object = ObjectInner::new(object, Rc::downgrade(&self.inner));
        let result = unsafe { (self.inner.ops.add_object)(self.inner.context, object.raw_ptr()) };
        if result != 0 {
            return Err(Error::Platform {
                operation: "ubus_add_object",
                code: result,
            });
        }
        OBJECT_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .insert(object.raw_ptr() as usize, Rc::downgrade(&object));
        });
        object.registered.set(true);
        self.inner.state.borrow_mut().objects.push(object);
        Ok(())
    }

    pub fn set_connection_lost_handler(&mut self, handler: impl FnMut() + 'static) {
        *self.inner.connection_lost_handler.borrow_mut() = Some(Box::new(handler));
        unsafe { (*self.inner.context).connection_lost = Some(connection_lost_trampoline) };
    }

    pub fn reregister_objects(&mut self) -> Result<()> {
        for object in &self.inner.state.borrow().objects {
            if object.registered.get() {
                continue;
            }
            let result =
                unsafe { (self.inner.ops.add_object)(self.inner.context, object.raw_ptr()) };
            if result != 0 {
                return Err(Error::Platform {
                    operation: "ubus_add_object",
                    code: result,
                });
            }
            object.registered.set(true);
        }
        Ok(())
    }

    #[cfg(test)]
    fn object_ptr_for_test(&self, index: usize) -> *mut raw::ubus_object {
        self.inner.state.borrow().objects[index].raw_ptr()
    }

    #[cfg(test)]
    unsafe fn invoke_raw_for_test(
        object: *mut raw::ubus_object,
        method: *const libc::c_char,
        request: *mut raw::ubus_request_data,
    ) -> libc::c_int {
        unsafe { method_trampoline(ptr::null_mut(), object, request, method, ptr::null_mut()) }
    }

    #[cfg(test)]
    fn is_attached_for_test(&self) -> bool {
        self.inner.state.borrow().fd_registered
    }

    #[cfg(test)]
    fn wants_uloop_for_test(&self) -> bool {
        self.inner.state.borrow().wants_uloop
    }

    #[cfg(test)]
    unsafe fn invoke_connection_lost_for_test(connection: &Self) {
        unsafe { connection_lost_trampoline(connection.inner.context) };
    }
}

unsafe extern "C" fn connection_lost_trampoline(context: *mut raw::ubus_context) {
    if context.is_null() {
        return;
    }
    let Some(connection) = CONNECTION_REGISTRY.with(|registry| {
        registry
            .borrow()
            .get(&(context as usize))
            .and_then(Weak::upgrade)
    }) else {
        return;
    };
    if connection.state.borrow().fd_registered {
        let socket = unsafe { &mut (*context).sock };
        let _ = unsafe { (connection.ops.fd_delete)(socket) };
        connection.state.borrow_mut().fd_registered = false;
    }
    for object in &connection.state.borrow().objects {
        object.registered.set(false);
    }
    let Some(mut handler) = connection.connection_lost_handler.borrow_mut().take() else {
        return;
    };
    let _ = catch_unwind(AssertUnwindSafe(|| handler()));
    *connection.connection_lost_handler.borrow_mut() = Some(handler);
}

impl Drop for UbusConnection {
    fn drop(&mut self) {
        if self.inner.dispatch_depth.get() > 0 {
            (self.inner.ops.defer_cleanup)(Rc::clone(&self.inner));
        }
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        let _ = CONNECTION_REGISTRY.try_with(|registry| {
            registry.borrow_mut().remove(&(self.context as usize));
        });
        let state = self.state.get_mut();
        for object in &state.objects {
            let _ = OBJECT_REGISTRY.try_with(|registry| {
                registry.borrow_mut().remove(&(object.raw_ptr() as usize));
            });
            let _ = unsafe { (self.ops.remove_object)(self.context, object.raw_ptr()) };
        }
        state.objects.clear();
        if state.fd_registered {
            let socket = unsafe { &mut (*self.context).sock };
            let _ = unsafe { (self.ops.fd_delete)(socket) };
        }
        unsafe { (self.ops.free)(self.context) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::ffi::CString;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FREED: AtomicBool = AtomicBool::new(false);
    static FAIL_RECONNECT: AtomicBool = AtomicBool::new(false);
    static FAIL_READD: AtomicBool = AtomicBool::new(false);
    static FD_ADD_CALLS: AtomicUsize = AtomicUsize::new(0);

    thread_local! {
        static TEST_DEFERRED_DROPS: RefCell<Vec<Rc<ConnectionInner>>> =
            const { RefCell::new(Vec::new()) };
    }

    unsafe extern "C" fn connect(_path: *const libc::c_char) -> *mut crate::raw::ubus_context {
        FREED.store(false, Ordering::SeqCst);
        EVENTS.lock().unwrap().push("connect");
        Box::into_raw(Box::new(crate::raw::ubus_context::default()))
    }

    unsafe extern "C" fn reconnect(
        _context: *mut crate::raw::ubus_context,
        _path: *const libc::c_char,
    ) -> libc::c_int {
        EVENTS.lock().unwrap().push("reconnect");
        if FAIL_RECONNECT.load(Ordering::SeqCst) {
            -6
        } else {
            0
        }
    }

    unsafe extern "C" fn free(context: *mut crate::raw::ubus_context) {
        EVENTS.lock().unwrap().push("free");
        FREED.store(true, Ordering::SeqCst);
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
        assert!(!FREED.load(Ordering::SeqCst));
        EVENTS.lock().unwrap().push("reply");
        0
    }

    unsafe extern "C" fn fd_add(
        socket: *mut crate::raw::uloop_fd,
        _flags: libc::c_uint,
    ) -> libc::c_int {
        let call = FD_ADD_CALLS.fetch_add(1, Ordering::SeqCst);
        EVENTS.lock().unwrap().push("fd_add");
        if call > 0 && FAIL_READD.load(Ordering::SeqCst) {
            return -5;
        }
        unsafe { (*socket).registered = true };
        0
    }

    unsafe extern "C" fn fd_delete(socket: *mut crate::raw::uloop_fd) -> libc::c_int {
        EVENTS.lock().unwrap().push("fd_delete");
        unsafe { (*socket).registered = false };
        0
    }

    fn defer_cleanup(connection: Rc<ConnectionInner>) {
        EVENTS.lock().unwrap().push("defer");
        TEST_DEFERRED_DROPS.with(|connections| connections.borrow_mut().push(connection));
    }

    fn run_deferred_cleanup() {
        EVENTS.lock().unwrap().push("next_tick");
        TEST_DEFERRED_DROPS.with(|connections| connections.borrow_mut().clear());
    }

    fn fake_ops() -> UbusOps {
        UbusOps {
            connect,
            reconnect,
            free,
            add_object,
            remove_object,
            send_reply,
            fd_add,
            fd_delete,
            defer_cleanup,
        }
    }

    struct DropProbe(Rc<Cell<usize>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn handler_drop_keeps_context_alive_until_the_next_event_loop_tick() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        let drops = Rc::new(Cell::new(0));
        let slot = Rc::new(RefCell::new(None));
        let callback_slot = Rc::clone(&slot);
        let probe = DropProbe(Rc::clone(&drops));
        let method = UbusMethod::new("status", move |mut request| {
            let _keep_alive = &probe;
            EVENTS.lock().unwrap().push("handler_start");
            drop(callback_slot.borrow_mut().take().unwrap());
            assert!(!FREED.load(Ordering::SeqCst));
            request.reply_json(r#"{"ok":true}"#).unwrap();
            EVENTS.lock().unwrap().push("handler_end");
            STATUS_OK
        })
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let object_pointer = connection.object_ptr_for_test(0);
        let method_name = CString::new("status").unwrap();
        let mut request = crate::raw::ubus_request_data::default();
        *slot.borrow_mut() = Some(connection);

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    object_pointer,
                    method_name.as_ptr(),
                    &mut request,
                )
            },
            STATUS_OK
        );
        assert!(slot.borrow().is_none());
        assert_eq!(drops.get(), 0);
        assert!(!FREED.load(Ordering::SeqCst));
        assert_eq!(
            &*EVENTS.lock().unwrap(),
            &[
                "connect",
                "add",
                "handler_start",
                "defer",
                "reply",
                "handler_end",
            ]
        );

        // This represents libubus finishing the current dispatch and uloop
        // invoking the zero-delay cleanup timer on its next turn.
        run_deferred_cleanup();
        assert!(FREED.load(Ordering::SeqCst));
        assert_eq!(drops.get(), 1);
        assert_eq!(
            &*EVENTS.lock().unwrap(),
            &[
                "connect",
                "add",
                "handler_start",
                "defer",
                "reply",
                "handler_end",
                "next_tick",
                "remove",
                "free"
            ]
        );
    }

    #[test]
    fn same_method_reentrancy_returns_error_without_borrowing_freed_storage() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        let raw_object = Rc::new(Cell::new(ptr::null_mut()));
        let callback_object = Rc::clone(&raw_object);
        let method_name = CString::new("nested").unwrap();
        let callback_name = method_name.clone();
        let method = UbusMethod::new("nested", move |_request| {
            let mut nested_request = crate::raw::ubus_request_data::default();
            assert_eq!(
                unsafe {
                    UbusConnection::invoke_raw_for_test(
                        callback_object.get(),
                        callback_name.as_ptr(),
                        &mut nested_request,
                    )
                },
                STATUS_UNKNOWN_ERROR
            );
            STATUS_OK
        })
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        raw_object.set(connection.object_ptr_for_test(0));
        let mut request = crate::raw::ubus_request_data::default();

        let status = unsafe {
            UbusConnection::invoke_raw_for_test(
                raw_object.get(),
                method_name.as_ptr(),
                &mut request,
            )
        };

        assert_eq!(status, STATUS_OK);
    }

    #[test]
    fn method_callback_panic_is_caught_at_ffi_boundary() {
        let _lock = TEST_LOCK.lock().unwrap();
        let method = UbusMethod::new("panic", |_request| panic!("handler failure")).unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let object = connection.object_ptr_for_test(0);
        let method_name = CString::new("panic").unwrap();
        let mut request = crate::raw::ubus_request_data::default();

        let status = unsafe {
            UbusConnection::invoke_raw_for_test(object, method_name.as_ptr(), &mut request)
        };

        assert_eq!(status, STATUS_UNKNOWN_ERROR);
    }

    #[test]
    fn attached_reconnect_detaches_and_adds_the_new_socket() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        FD_ADD_CALLS.store(0, Ordering::SeqCst);
        FAIL_RECONNECT.store(false, Ordering::SeqCst);
        FAIL_READD.store(false, Ordering::SeqCst);
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.attach_uloop().unwrap();

        connection.reconnect(None).unwrap();

        assert!(connection.is_attached_for_test());
        drop(connection);
        assert_eq!(
            &*EVENTS.lock().unwrap(),
            &[
                "connect",
                "fd_add",
                "fd_delete",
                "reconnect",
                "fd_add",
                "fd_delete",
                "free"
            ]
        );
    }

    #[test]
    fn unattached_reconnect_does_not_add_socket() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        FD_ADD_CALLS.store(0, Ordering::SeqCst);
        FAIL_RECONNECT.store(false, Ordering::SeqCst);
        FAIL_READD.store(false, Ordering::SeqCst);
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();

        connection.reconnect(None).unwrap();

        assert!(!connection.is_attached_for_test());
        drop(connection);
        assert_eq!(&*EVENTS.lock().unwrap(), &["connect", "reconnect", "free"]);
    }

    #[test]
    fn connection_loss_detaches_and_reregisters_existing_object_without_duplication() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        let losses = Rc::new(Cell::new(0));
        let callback_losses = Rc::clone(&losses);
        let method = UbusMethod::new("status", |_request| STATUS_OK).unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.attach_uloop().unwrap();
        connection.register_object(object).unwrap();
        connection
            .set_connection_lost_handler(move || callback_losses.set(callback_losses.get() + 1));
        let object_pointer = connection.object_ptr_for_test(0);

        unsafe { UbusConnection::invoke_connection_lost_for_test(&connection) };
        assert_eq!(losses.get(), 1);
        assert!(!connection.is_attached_for_test());
        connection.reconnect(None).unwrap();
        connection.reregister_objects().unwrap();

        assert_eq!(connection.object_ptr_for_test(0), object_pointer);
        assert_eq!(connection.inner.state.borrow().objects.len(), 1);
        assert_eq!(
            EVENTS
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "add")
                .count(),
            2
        );
    }

    #[test]
    fn reconnect_readd_failure_leaves_connection_detached() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        FD_ADD_CALLS.store(0, Ordering::SeqCst);
        FAIL_RECONNECT.store(false, Ordering::SeqCst);
        FAIL_READD.store(true, Ordering::SeqCst);
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.attach_uloop().unwrap();

        assert!(connection.reconnect(None).is_err());

        assert!(!connection.is_attached_for_test());
        drop(connection);
        assert_eq!(
            &*EVENTS.lock().unwrap(),
            &[
                "connect",
                "fd_add",
                "fd_delete",
                "reconnect",
                "fd_add",
                "free"
            ]
        );
    }

    #[test]
    fn reconnect_failure_preserves_uloop_intent_for_a_successful_retry() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        FD_ADD_CALLS.store(0, Ordering::SeqCst);
        FAIL_READD.store(false, Ordering::SeqCst);
        FAIL_RECONNECT.store(true, Ordering::SeqCst);
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.attach_uloop().unwrap();

        assert!(connection.reconnect(None).is_err());
        assert!(!connection.is_attached_for_test());
        assert!(connection.wants_uloop_for_test());
        FAIL_RECONNECT.store(false, Ordering::SeqCst);
        connection.reconnect(None).unwrap();

        assert!(connection.is_attached_for_test());
        drop(connection);
        assert_eq!(
            &*EVENTS.lock().unwrap(),
            &[
                "connect",
                "fd_add",
                "fd_delete",
                "reconnect",
                "reconnect",
                "fd_add",
                "fd_delete",
                "free"
            ]
        );
    }

    #[test]
    fn readd_failure_preserves_uloop_intent_for_a_successful_retry() {
        let _lock = TEST_LOCK.lock().unwrap();
        EVENTS.lock().unwrap().clear();
        FD_ADD_CALLS.store(0, Ordering::SeqCst);
        FAIL_RECONNECT.store(false, Ordering::SeqCst);
        FAIL_READD.store(true, Ordering::SeqCst);
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.attach_uloop().unwrap();

        assert!(connection.reconnect(None).is_err());
        assert!(!connection.is_attached_for_test());
        assert!(connection.wants_uloop_for_test());
        FAIL_READD.store(false, Ordering::SeqCst);
        connection.reconnect(None).unwrap();

        assert!(connection.is_attached_for_test());
        drop(connection);
        assert_eq!(
            &*EVENTS.lock().unwrap(),
            &[
                "connect",
                "fd_add",
                "fd_delete",
                "reconnect",
                "fd_add",
                "reconnect",
                "fd_add",
                "fd_delete",
                "free"
            ]
        );
    }
}
