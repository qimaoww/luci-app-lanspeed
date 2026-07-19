use crate::{raw, BlobBuf, Error, Result};
use std::cell::{RefCell, UnsafeCell};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::rc::{Rc, Weak};

pub const STATUS_OK: libc::c_int = raw::ubus_msg_status_UBUS_STATUS_OK.0 as libc::c_int;
pub const STATUS_INVALID_ARGUMENT: libc::c_int =
    raw::ubus_msg_status_UBUS_STATUS_INVALID_ARGUMENT.0 as libc::c_int;
pub const STATUS_UNKNOWN_ERROR: libc::c_int =
    raw::ubus_msg_status_UBUS_STATUS_UNKNOWN_ERROR.0 as libc::c_int;

const BLOB_ATTR_HEADER_LEN: usize = std::mem::size_of::<raw::blob_attr>();
const BLOB_ATTR_LEN_MASK: u32 = 0x00ff_ffff;
const BLOB_ATTR_ID_MASK: u32 = 0x7f00_0000;
const BLOB_ATTR_ID_SHIFT: u32 = 24;
const BLOB_ATTR_EXTENDED: u32 = 0x8000_0000;
const BLOB_ALIGNMENT: usize = 4;
const BLOBMSG_HEADER_LEN: usize = std::mem::size_of::<u16>();
const INVALID_BLOBMSG_FIELD: Error = Error::InvalidData("invalid blobmsg field");

#[derive(Clone, Copy)]
struct BlobMessagePayload {
    data: *mut libc::c_void,
    length: libc::c_uint,
    start: usize,
    end: usize,
}

fn blob_raw_length(encoded: u32) -> usize {
    (encoded & BLOB_ATTR_LEN_MASK) as usize
}

fn blob_type(encoded: u32) -> u32 {
    (encoded & BLOB_ATTR_ID_MASK) >> BLOB_ATTR_ID_SHIFT
}

fn blob_padded_length(raw_length: usize) -> Result<usize> {
    raw_length
        .checked_add(BLOB_ALIGNMENT - 1)
        .map(|length| length & !(BLOB_ALIGNMENT - 1))
        .ok_or(INVALID_BLOBMSG_FIELD)
}

unsafe fn read_be_u16(pointer: *const u8) -> u16 {
    u16::from_be(unsafe { ptr::read_unaligned(pointer.cast::<u16>()) })
}

unsafe fn read_be_u32(pointer: *const u8) -> u32 {
    u32::from_be(unsafe { ptr::read_unaligned(pointer.cast::<u32>()) })
}

fn blobmsg_extended_header_length(attribute: *const u8, payload_length: usize) -> Result<usize> {
    if payload_length < BLOBMSG_HEADER_LEN {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    let header = unsafe { attribute.add(BLOB_ATTR_HEADER_LEN) };
    // The caller has already proved that the complete attribute payload is
    // readable, including the two-byte packed blobmsg header.
    let name_length = usize::from(unsafe { read_be_u16(header) });
    let unpadded_length = BLOBMSG_HEADER_LEN
        .checked_add(name_length)
        .and_then(|length| length.checked_add(1))
        .ok_or(INVALID_BLOBMSG_FIELD)?;
    let header_length = blob_padded_length(unpadded_length)?;
    if header_length > payload_length {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    // `unpadded_length <= header_length <= payload_length`, so the name's
    // terminating byte is within the already validated attribute.
    let terminator = unsafe { header.add(BLOBMSG_HEADER_LEN + name_length) };
    if unsafe { terminator.read() } != 0 {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    Ok(header_length)
}

fn validate_blobmsg_attributes(data: *mut u8, length: usize) -> Result<()> {
    let mut offset = 0usize;
    while offset < length {
        let remaining = length - offset;
        if remaining < BLOB_ATTR_HEADER_LEN {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        let attribute = unsafe { data.add(offset) };
        // The remaining message contains a complete blob header at this
        // offset, so an unaligned four-byte read is valid.
        let encoded = unsafe { read_be_u32(attribute) };
        let raw_length = blob_raw_length(encoded);
        if raw_length < BLOB_ATTR_HEADER_LEN || raw_length > remaining {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        let padded_length = blob_padded_length(raw_length)?;
        if padded_length > remaining {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        if blob_type(encoded) > raw::blobmsg_type_BLOBMSG_TYPE_LAST.0 {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        if encoded & BLOB_ATTR_EXTENDED == 0 {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        blobmsg_extended_header_length(attribute, raw_length - BLOB_ATTR_HEADER_LEN)?;
        offset += padded_length;
    }
    Ok(())
}

fn blobmsg_payload(message: *mut raw::blob_attr) -> Result<BlobMessagePayload> {
    if message.is_null() {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    // libubus guarantees that a callback message points to a readable blob
    // header and to the complete span encoded by that header. All subsequent
    // reads are bounded against that encoded outer span before they occur.
    let encoded = unsafe { read_be_u32(message.cast::<u8>()) };
    let raw_length = blob_raw_length(encoded);
    if raw_length < BLOB_ATTR_HEADER_LEN || encoded & BLOB_ATTR_EXTENDED != 0 {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    let length = raw_length - BLOB_ATTR_HEADER_LEN;
    let data = unsafe { message.cast::<u8>().add(BLOB_ATTR_HEADER_LEN) };
    let start = data as usize;
    let end = start.checked_add(length).ok_or(INVALID_BLOBMSG_FIELD)?;
    validate_blobmsg_attributes(data, length)?;
    Ok(BlobMessagePayload {
        data: data.cast(),
        length: libc::c_uint::try_from(length).map_err(|_| INVALID_BLOBMSG_FIELD)?,
        start,
        end,
    })
}

fn parse_blobmsg_field(
    policy: &raw::blobmsg_policy,
    payload: BlobMessagePayload,
) -> Result<*mut raw::blob_attr> {
    let mut field = ptr::null_mut();
    let result = unsafe { raw::blobmsg_parse(policy, 1, &mut field, payload.data, payload.length) };
    if result == 0 {
        Ok(field)
    } else {
        Err(INVALID_BLOBMSG_FIELD)
    }
}

fn blobmsg_name_matches(attribute: *const u8, raw_length: usize, expected: &[u8]) -> Result<bool> {
    let payload_length = raw_length
        .checked_sub(BLOB_ATTR_HEADER_LEN)
        .ok_or(INVALID_BLOBMSG_FIELD)?;
    blobmsg_extended_header_length(attribute, payload_length)?;
    let header = unsafe { attribute.add(BLOB_ATTR_HEADER_LEN) };
    let name_length = usize::from(unsafe { read_be_u16(header) });
    if name_length != expected.len() {
        return Ok(false);
    }
    // The validated extended header contains all name bytes and their NUL
    // terminator, so only the declared name span is exposed as a slice.
    let name = unsafe { std::slice::from_raw_parts(header.add(BLOBMSG_HEADER_LEN), name_length) };
    Ok(name == expected)
}

fn unique_string_field(
    payload: BlobMessagePayload,
    expected_name: &[u8],
) -> Result<Option<*mut raw::blob_attr>> {
    let data = payload.data.cast::<u8>();
    let length = usize::try_from(payload.length).map_err(|_| INVALID_BLOBMSG_FIELD)?;
    let mut offset = 0usize;
    let mut found = None;
    while offset < length {
        let remaining = length - offset;
        if remaining < BLOB_ATTR_HEADER_LEN {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        let attribute = unsafe { data.add(offset) };
        let encoded = unsafe { read_be_u32(attribute) };
        let raw_length = blob_raw_length(encoded);
        if raw_length < BLOB_ATTR_HEADER_LEN
            || raw_length > remaining
            || encoded & BLOB_ATTR_EXTENDED == 0
        {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        let padded_length = blob_padded_length(raw_length)?;
        if padded_length > remaining {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        if blobmsg_name_matches(attribute, raw_length, expected_name)? {
            if found.is_some() || blob_type(encoded) != raw::blobmsg_type_BLOBMSG_TYPE_STRING.0 {
                return Err(INVALID_BLOBMSG_FIELD);
            }
            found = Some(attribute.cast::<raw::blob_attr>());
        }
        offset += padded_length;
    }
    Ok(found)
}

fn read_blobmsg_string(field: *mut raw::blob_attr, payload: BlobMessagePayload) -> Result<String> {
    let field_start = field as usize;
    if field.is_null()
        || field_start < payload.start
        || field_start
            .checked_add(BLOB_ATTR_HEADER_LEN)
            .is_none_or(|end| end > payload.end)
    {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    // The field header is entirely inside the validated outer payload.
    let encoded = unsafe { read_be_u32(field.cast::<u8>()) };
    let raw_length = blob_raw_length(encoded);
    let field_end = field_start
        .checked_add(raw_length)
        .ok_or(INVALID_BLOBMSG_FIELD)?;
    if raw_length < BLOB_ATTR_HEADER_LEN
        || field_end > payload.end
        || encoded & BLOB_ATTR_EXTENDED == 0
        || blob_type(encoded) != raw::blobmsg_type_BLOBMSG_TYPE_STRING.0
    {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    let payload_length = raw_length - BLOB_ATTR_HEADER_LEN;
    let header_length = blobmsg_extended_header_length(field.cast::<u8>(), payload_length)?;
    let data_length = payload_length
        .checked_sub(header_length)
        .filter(|length| *length > 0)
        .ok_or(INVALID_BLOBMSG_FIELD)?;
    let data = unsafe { field.cast::<u8>().add(BLOB_ATTR_HEADER_LEN + header_length) };
    // Header and raw-length checks above prove this complete data range lies
    // inside the outer message; only now is it exposed as a Rust slice.
    let bytes = unsafe { std::slice::from_raw_parts(data, data_length) };
    let Some(value) = bytes.strip_suffix(&[0]) else {
        return Err(INVALID_BLOBMSG_FIELD);
    };
    if value.contains(&0) {
        return Err(INVALID_BLOBMSG_FIELD);
    }
    let value = std::str::from_utf8(value).map_err(|_| INVALID_BLOBMSG_FIELD)?;
    Ok(value.to_owned())
}

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
    policies: Vec<(CString, raw::blobmsg_type)>,
    handler: Box<Handler>,
}

impl UbusMethod {
    pub fn new(
        name: &str,
        handler: impl for<'request> FnMut(UbusRequest<'request>) -> libc::c_int + 'static,
    ) -> Result<Self> {
        Ok(Self {
            name: CString::new(name)?,
            policies: Vec::new(),
            handler: Box::new(handler),
        })
    }

    pub fn with_string_policy(mut self, name: &str) -> Result<Self> {
        let policy_count = self
            .policies
            .len()
            .checked_add(1)
            .ok_or(Error::InvalidData("too many ubus policies"))?;
        libc::c_int::try_from(policy_count)
            .map_err(|_| Error::InvalidData("too many ubus policies"))?;
        self.policies
            .push((CString::new(name)?, raw::blobmsg_type_BLOBMSG_TYPE_STRING));
        Ok(self)
    }
}

pub struct UbusRequest<'request> {
    connection: Rc<ConnectionInner>,
    request: *mut raw::ubus_request_data,
    message: *mut raw::blob_attr,
    policy_names: &'request [CString],
    policies: &'request [raw::blobmsg_policy],
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

    pub fn string(&self, name: &str) -> Result<Option<String>> {
        let Some(index) = self
            .policy_names
            .iter()
            .position(|policy_name| policy_name.as_bytes() == name.as_bytes())
        else {
            return Err(INVALID_BLOBMSG_FIELD);
        };
        let policy = self.policies.get(index).ok_or(INVALID_BLOBMSG_FIELD)?;
        if policy.type_ != raw::blobmsg_type_BLOBMSG_TYPE_STRING {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        let payload = blobmsg_payload(self.message)?;
        if payload.length == 0 {
            return Ok(None);
        }
        let typed_field = parse_blobmsg_field(policy, payload)?;
        let named_field = unique_string_field(payload, name.as_bytes())?;
        let Some(named_field) = named_field else {
            return if typed_field.is_null() {
                Ok(None)
            } else {
                Err(INVALID_BLOBMSG_FIELD)
            };
        };
        if typed_field != named_field {
            return Err(INVALID_BLOBMSG_FIELD);
        }
        read_blobmsg_string(typed_field, payload).map(Some)
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
    policy_names: Vec<CString>,
    policies: Box<[raw::blobmsg_policy]>,
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
            .map(|method| {
                let (policy_names, policy_types): (Vec<_>, Vec<_>) =
                    method.policies.into_iter().unzip();
                let policies = policy_names
                    .iter()
                    .zip(policy_types)
                    .map(|(name, type_)| raw::blobmsg_policy {
                        name: name.as_ptr(),
                        type_,
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice();
                MethodCell {
                    name: method.name,
                    policy_names,
                    policies,
                    handler: RefCell::new(Some(method.handler)),
                }
            })
            .collect::<Vec<_>>();
        let raw_methods = methods
            .iter()
            .map(|method| raw::ubus_method {
                name: method.name.as_ptr(),
                handler: Some(method_trampoline),
                mask: 0,
                tags: 0,
                policy: if method.policies.is_empty() {
                    ptr::null()
                } else {
                    method.policies.as_ptr()
                },
                n_policy: method.policies.len() as libc::c_int,
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
    message: *mut raw::blob_attr,
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
        message,
        policy_names: &method.policy_names,
        policies: &method.policies,
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
        message: *mut raw::blob_attr,
    ) -> libc::c_int {
        unsafe { method_trampoline(ptr::null_mut(), object, request, method, message) }
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

    unsafe fn first_blobmsg_field_for_test(message: *mut raw::blob_attr) -> *mut u8 {
        unsafe {
            message
                .cast::<u8>()
                .add(std::mem::size_of::<raw::blob_attr>())
        }
    }

    unsafe fn blobmsg_field_data_for_test(field: *mut u8) -> *mut u8 {
        let header = unsafe { field.add(std::mem::size_of::<raw::blob_attr>()) };
        let name_length = u16::from_be(unsafe { ptr::read_unaligned(header.cast::<u16>()) });
        let header_length = (std::mem::size_of::<u16>() + usize::from(name_length) + 1 + 3) & !3;
        unsafe { header.add(header_length) }
    }

    unsafe fn second_blobmsg_field_for_test(message: *mut raw::blob_attr) -> *mut u8 {
        let first = unsafe { first_blobmsg_field_for_test(message) };
        let raw_length = blob_raw_length(unsafe { read_be_u32(first) });
        unsafe { first.add(blob_padded_length(raw_length).unwrap()) }
    }

    unsafe fn rename_blobmsg_field_for_test(field: *mut u8, name: &[u8]) {
        let header = unsafe { field.add(std::mem::size_of::<raw::blob_attr>()) };
        let name_length = usize::from(unsafe { read_be_u16(header) });
        assert_eq!(name.len(), name_length);
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                header.add(std::mem::size_of::<u16>()),
                name.len(),
            )
        };
    }

    #[test]
    fn string_policy_reads_identity_key() {
        let _lock = TEST_LOCK.lock().unwrap();
        let seen = Rc::new(RefCell::new(None));
        let callback_seen = Rc::clone(&seen);
        let method = UbusMethod::new("client_connections", move |request| {
            *callback_seen.borrow_mut() = request.string("identity_key").unwrap();
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json(r#"{"identity_key":"02:00:00:00:00:42@eth1"}"#).unwrap();
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert_eq!(seen.borrow().as_deref(), Some("02:00:00:00:00:42@eth1"));
    }

    #[test]
    fn missing_string_policy_value_returns_none() {
        let _lock = TEST_LOCK.lock().unwrap();
        let seen = Rc::new(RefCell::new(None));
        let callback_seen = Rc::clone(&seen);
        let method = UbusMethod::new("client_connections", move |request| {
            *callback_seen.borrow_mut() = Some(request.string("identity_key"));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json("{}").unwrap();
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert_eq!(*seen.borrow(), Some(Ok(None)));
    }

    #[test]
    fn wrong_string_policy_type_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("identity_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json(r#"{"identity_key":7}"#).unwrap();
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
    }

    #[test]
    fn undeclared_string_policy_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("other_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json("{}").unwrap();
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
    }

    #[test]
    fn interior_nul_string_policy_name_is_rejected() {
        let method = UbusMethod::new("client_connections", |_request| STATUS_OK).unwrap();

        let result = method.with_string_policy("identity\0key");

        assert!(matches!(result, Err(Error::InteriorNul)));
    }

    #[test]
    fn malformed_blobmsg_extension_header_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("identity_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json(r#"{"identity_key":"client"}"#).unwrap();
        let field = unsafe { first_blobmsg_field_for_test(message.head()) };
        let extension_header = unsafe { field.add(std::mem::size_of::<raw::blob_attr>()) };
        let name_length =
            u16::from_be(unsafe { ptr::read_unaligned(extension_header.cast::<u16>()) });
        let terminator = unsafe {
            extension_header
                .add(std::mem::size_of::<u16>())
                .add(usize::from(name_length))
        };
        unsafe { terminator.write(b'x') };
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
    }

    #[test]
    fn invalid_utf8_string_policy_value_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("identity_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json(r#"{"identity_key":"client"}"#).unwrap();
        let field = unsafe { first_blobmsg_field_for_test(message.head()) };
        let value = unsafe { blobmsg_field_data_for_test(field) };
        unsafe { value.write(0xff) };
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
    }

    #[test]
    fn embedded_nul_with_invalid_tail_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("identity_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json(r#"{"identity_key":"four"}"#).unwrap();
        let field = unsafe { first_blobmsg_field_for_test(message.head()) };
        let value = unsafe { blobmsg_field_data_for_test(field) };
        let invalid_value = [b'o', b'k', 0, 0xff, 0];
        unsafe {
            ptr::copy_nonoverlapping(invalid_value.as_ptr(), value, invalid_value.len());
        }
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
    }

    #[test]
    fn duplicate_name_with_wrong_type_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("identity_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json(r#"{"identity_key":"client","another__key":7}"#).unwrap();
        let duplicate = unsafe { second_blobmsg_field_for_test(message.head()) };
        unsafe { rename_blobmsg_field_for_test(duplicate, b"identity_key") };
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
    }

    #[test]
    fn duplicate_string_name_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("identity_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message =
            BlobBuf::from_json(r#"{"identity_key":"client","another__key":"second"}"#).unwrap();
        let duplicate = unsafe { second_blobmsg_field_for_test(message.head()) };
        unsafe { rename_blobmsg_field_for_test(duplicate, b"identity_key") };
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
    }

    #[test]
    fn non_extended_top_level_field_returns_invalid_data() {
        let _lock = TEST_LOCK.lock().unwrap();
        let saw_invalid_data = Rc::new(Cell::new(false));
        let callback_saw_invalid_data = Rc::clone(&saw_invalid_data);
        let method = UbusMethod::new("client_connections", move |request| {
            callback_saw_invalid_data.set(matches!(
                request.string("identity_key"),
                Err(Error::InvalidData("invalid blobmsg field"))
            ));
            STATUS_OK
        })
        .unwrap()
        .with_string_policy("identity_key")
        .unwrap();
        let object = UbusObject::new("lanspeed", vec![method]).unwrap();
        let mut connection = UbusConnection::connect_with(None, fake_ops()).unwrap();
        connection.register_object(object).unwrap();
        let message = BlobBuf::from_json(r#"{"identity_key":"client"}"#).unwrap();
        let field = unsafe { first_blobmsg_field_for_test(message.head()) };
        let encoded = unsafe { read_be_u32(field) } & !BLOB_ATTR_EXTENDED;
        unsafe { ptr::write_unaligned(field.cast::<u32>(), encoded.to_be()) };
        let mut request = crate::raw::ubus_request_data::default();
        let method_name = CString::new("client_connections").unwrap();

        assert_eq!(
            unsafe {
                UbusConnection::invoke_raw_for_test(
                    connection.object_ptr_for_test(0),
                    method_name.as_ptr(),
                    &mut request,
                    message.head(),
                )
            },
            STATUS_OK
        );
        assert!(saw_invalid_data.get());
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
                    ptr::null_mut(),
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
                        ptr::null_mut(),
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
                ptr::null_mut(),
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
            UbusConnection::invoke_raw_for_test(
                object,
                method_name.as_ptr(),
                &mut request,
                ptr::null_mut(),
            )
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
