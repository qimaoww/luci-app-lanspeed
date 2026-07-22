use crate::{codec, BlobBuf, Error, Result};
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    marker::PhantomData,
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

pub const STATUS_OK: libc::c_int = 0;
pub const STATUS_INVALID_ARGUMENT: libc::c_int = 2;
pub const STATUS_UNKNOWN_ERROR: libc::c_int = 9;

const STATUS_CONNECTION_FAILED: libc::c_int = 10;
const STATUS_TIMEOUT: libc::c_int = 7;
const UBUS_VERSION: u8 = 0;
const UBUS_MSG_HELLO: u8 = 0;
const UBUS_MSG_STATUS: u8 = 1;
const UBUS_MSG_DATA: u8 = 2;
const UBUS_MSG_LOOKUP: u8 = 4;
const UBUS_MSG_INVOKE: u8 = 5;
const UBUS_MSG_ADD_OBJECT: u8 = 6;
const UBUS_ATTR_STATUS: u8 = 1;
const UBUS_ATTR_OBJPATH: u8 = 2;
const UBUS_ATTR_OBJID: u8 = 3;
const UBUS_ATTR_METHOD: u8 = 4;
const UBUS_ATTR_SIGNATURE: u8 = 6;
const UBUS_ATTR_DATA: u8 = 7;
const UBUS_ATTR_NO_REPLY: u8 = 10;
const DEFAULT_SOCKET: &str = "/var/run/ubus/ubus.sock";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_QUEUED_BYTES: usize = codec::MAX_MESSAGE_LEN * 4;
const FRAME_HEADER_LEN: usize = 8;
const MIN_FRAME_LEN: usize = FRAME_HEADER_LEN + 4;
const READ_CHUNK_LEN: usize = 65_536;
// Bound one loop turn so an input flood cannot starve uloop timers or signals.
const MAX_READ_BYTES_PER_BATCH: usize = 256 * 1_024;
const MAX_READ_FRAMES_PER_BATCH: usize = 256;

type Handler = dyn for<'request> FnMut(UbusRequest<'request>) -> libc::c_int;

thread_local! {
    static CONNECTIONS: RefCell<Vec<Weak<ConnectionInner>>> = const { RefCell::new(Vec::new()) };
}

pub struct UbusMethod {
    name: String,
    policies: Vec<(String, u8)>,
    handler: Box<Handler>,
}

impl UbusMethod {
    pub fn new(
        name: &str,
        handler: impl for<'request> FnMut(UbusRequest<'request>) -> libc::c_int + 'static,
    ) -> Result<Self> {
        validate_name(name, "ubus method")?;
        Ok(Self {
            name: name.to_owned(),
            policies: Vec::new(),
            handler: Box::new(handler),
        })
    }

    pub fn with_string_policy(mut self, name: &str) -> Result<Self> {
        validate_name(name, "ubus policy")?;
        if self.policies.iter().any(|(candidate, _)| candidate == name) {
            return Err(Error::InvalidData("duplicate ubus policy"));
        }
        self.policies.push((name.to_owned(), codec::BLOBMSG_STRING));
        Ok(self)
    }
}

fn validate_name(name: &str, _kind: &'static str) -> Result<()> {
    if name.is_empty() || name.len() > 255 || name.as_bytes().contains(&0) {
        Err(Error::InvalidData("invalid ubus name"))
    } else {
        Ok(())
    }
}

pub struct UbusObject {
    name: String,
    methods: Vec<UbusMethod>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl UbusObject {
    pub fn new(name: &str, methods: Vec<UbusMethod>) -> Result<Self> {
        validate_name(name, "ubus object")?;
        if methods.is_empty() || methods.len() > 1_024 {
            return Err(Error::InvalidData("invalid ubus method count"));
        }
        for (index, method) in methods.iter().enumerate() {
            if methods[..index]
                .iter()
                .any(|candidate| candidate.name == method.name)
            {
                return Err(Error::InvalidData("duplicate ubus method"));
            }
        }
        Ok(Self {
            name: name.to_owned(),
            methods,
            _not_send_or_sync: PhantomData,
        })
    }
}

struct MethodInner {
    name: String,
    policies: Vec<(String, u8)>,
    handler: RefCell<Option<Box<Handler>>>,
}

struct ObjectInner {
    name: String,
    methods: Vec<MethodInner>,
    id: Cell<Option<u32>>,
    type_id: Cell<Option<u32>>,
}

impl From<UbusObject> for ObjectInner {
    fn from(object: UbusObject) -> Self {
        Self {
            name: object.name,
            methods: object
                .methods
                .into_iter()
                .map(|method| MethodInner {
                    name: method.name,
                    policies: method.policies,
                    handler: RefCell::new(Some(method.handler)),
                })
                .collect(),
            id: Cell::new(None),
            type_id: Cell::new(None),
        }
    }
}

#[derive(Clone, Copy)]
struct RequestMeta {
    seq: u16,
    peer: u32,
    object: u32,
}

pub struct UbusRequest<'request> {
    connection: Rc<ConnectionInner>,
    request: RequestMeta,
    message: Vec<u8>,
    policies: &'request [(String, u8)],
    _lifetime: PhantomData<&'request mut ()>,
}

impl UbusRequest<'_> {
    pub fn reply_json(&mut self, json: &str) -> Result<()> {
        let message = BlobBuf::from_json(json)?;
        let root = codec::parse_attr(message.bytes())?;
        let mut attrs = codec::encode_u32_attr(UBUS_ATTR_OBJID, self.request.object)?;
        attrs.extend_from_slice(&codec::encode_attr(UBUS_ATTR_DATA, false, root.payload)?);
        let body = codec::encode_root(&attrs)?;
        self.connection
            .queue_frame(UBUS_MSG_DATA, self.request.seq, self.request.peer, body)
    }

    pub fn string(&self, name: &str) -> Result<Option<String>> {
        let Some((_, kind)) = self
            .policies
            .iter()
            .find(|(candidate, _)| candidate == name)
        else {
            return Err(Error::InvalidData("unknown ubus policy"));
        };
        if *kind != codec::BLOBMSG_STRING {
            return Err(Error::InvalidData("ubus policy is not a string"));
        }
        codec::find_string_field(&self.message, name)
    }
}

struct Outbound {
    bytes: Vec<u8>,
    offset: usize,
}

#[derive(Default)]
struct PendingRequest {
    object_index: Option<usize>,
    value: Option<u32>,
    status: Option<libc::c_int>,
}

struct ConnectionState {
    stream: Option<UnixStream>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    outbound: VecDeque<Outbound>,
    queued_bytes: usize,
    objects: Vec<Rc<ObjectInner>>,
    pending: HashMap<u16, PendingRequest>,
    next_seq: u16,
    local_id: u32,
    attached: bool,
    registered_in_loop: bool,
    connection_lost_notified: bool,
}

struct ConnectionInner {
    path: PathBuf,
    self_weak: Weak<ConnectionInner>,
    state: RefCell<ConnectionState>,
    connection_lost_handler: RefCell<Option<Box<dyn FnMut()>>>,
    dispatch_depth: Cell<usize>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

pub struct UbusConnection {
    inner: Rc<ConnectionInner>,
}

impl UbusConnection {
    pub fn connect(path: Option<&str>) -> Result<Self> {
        let path = PathBuf::from(path.unwrap_or(DEFAULT_SOCKET));
        let inner = Rc::new_cyclic(|self_weak| ConnectionInner {
            path,
            self_weak: self_weak.clone(),
            state: RefCell::new(ConnectionState {
                stream: None,
                read_buffer: Vec::with_capacity(65_536),
                read_offset: 0,
                outbound: VecDeque::new(),
                queued_bytes: 0,
                objects: Vec::new(),
                pending: HashMap::new(),
                next_seq: 0,
                local_id: 0,
                attached: false,
                registered_in_loop: false,
                connection_lost_notified: false,
            }),
            connection_lost_handler: RefCell::new(None),
            dispatch_depth: Cell::new(0),
            _not_send_or_sync: PhantomData,
        });
        inner.open()?;
        Ok(Self { inner })
    }

    pub fn attach_uloop(&mut self) -> Result<()> {
        let mut state = self.inner.state.borrow_mut();
        state.attached = true;
        if !state.registered_in_loop {
            CONNECTIONS
                .with(|connections| connections.borrow_mut().push(Rc::downgrade(&self.inner)));
            state.registered_in_loop = true;
        }
        Ok(())
    }

    pub fn reconnect(&mut self, path: Option<&str>) -> Result<()> {
        if path.is_some_and(|path| PathBuf::from(path) != self.inner.path) {
            return Err(Error::InvalidData(
                "changing the ubus socket path on reconnect is unsupported",
            ));
        }
        self.inner.open()
    }

    pub fn lookup_id(&mut self, path: &str) -> Result<u32> {
        validate_name(path, "ubus lookup")?;
        let attrs = codec::encode_string_attr(UBUS_ATTR_OBJPATH, path)?;
        let body = codec::encode_root(&attrs)?;
        let seq = self.inner.next_sequence();
        self.inner
            .queue_pending_frame(seq, PendingRequest::default(), UBUS_MSG_LOOKUP, 0, body)?;
        self.inner.wait_pending(seq)
    }

    pub fn register_object(&mut self, object: UbusObject) -> Result<()> {
        let index = {
            let mut state = self.inner.state.borrow_mut();
            state.objects.push(Rc::new(ObjectInner::from(object)));
            state.objects.len() - 1
        };
        self.inner.register_object(index)
    }

    pub fn reregister_objects(&mut self) -> Result<()> {
        let count = self.inner.state.borrow().objects.len();
        for index in 0..count {
            self.inner.register_object(index)?;
        }
        Ok(())
    }

    pub fn set_connection_lost_handler(&mut self, handler: impl FnMut() + 'static) {
        *self.inner.connection_lost_handler.borrow_mut() = Some(Box::new(handler));
    }
}

impl ConnectionInner {
    fn open(&self) -> Result<()> {
        let mut stream =
            UnixStream::connect(&self.path).map_err(|error| io_error("ubus_connect", error))?;
        stream
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|error| io_error("ubus_set_timeout", error))?;
        let mut header = [0u8; 12];
        stream
            .read_exact(&mut header)
            .map_err(|error| io_error("ubus_read_hello", error))?;
        if header[0] != UBUS_VERSION || header[1] != UBUS_MSG_HELLO {
            return Err(Error::InvalidData("invalid ubus hello header"));
        }
        let peer = u32::from_be_bytes(header[4..8].try_into().unwrap());
        if peer <= 1 {
            return Err(Error::InvalidData("invalid ubus client id"));
        }
        let encoded = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let raw_len = (encoded & 0x00ff_ffff) as usize;
        if raw_len < 4 || raw_len > codec::MAX_MESSAGE_LEN {
            return Err(Error::InvalidData("invalid ubus hello payload"));
        }
        let mut body = vec![0u8; raw_len];
        body[..4].copy_from_slice(&header[8..12]);
        stream
            .read_exact(&mut body[4..])
            .map_err(|error| io_error("ubus_read_hello", error))?;
        let root = codec::parse_attr(&body)?;
        if root.id != 0 || root.raw_len != raw_len {
            return Err(Error::InvalidData("invalid ubus hello blob"));
        }
        stream
            .set_read_timeout(None)
            .map_err(|error| io_error("ubus_set_timeout", error))?;
        stream
            .set_nonblocking(true)
            .map_err(|error| io_error("ubus_set_nonblocking", error))?;
        let mut state = self.state.borrow_mut();
        state.stream = Some(stream);
        state.read_buffer.clear();
        state.read_offset = 0;
        state.outbound.clear();
        state.queued_bytes = 0;
        state.pending.clear();
        state.local_id = peer;
        state.connection_lost_notified = false;
        for object in &state.objects {
            object.id.set(None);
            object.type_id.set(None);
        }
        Ok(())
    }

    fn next_sequence(&self) -> u16 {
        let mut state = self.state.borrow_mut();
        state.next_seq = state.next_seq.wrapping_add(1);
        if state.next_seq == 0 {
            state.next_seq = 1;
        }
        state.next_seq
    }

    fn register_object(&self, index: usize) -> Result<()> {
        let object = self
            .state
            .borrow()
            .objects
            .get(index)
            .cloned()
            .ok_or(Error::InvalidData("unknown ubus object"))?;
        let body = encode_object_registration(&object)?;
        let seq = self.next_sequence();
        self.queue_pending_frame(
            seq,
            PendingRequest {
                object_index: Some(index),
                ..PendingRequest::default()
            },
            UBUS_MSG_ADD_OBJECT,
            0,
            body,
        )?;
        self.wait_pending(seq).map(|_| ())
    }

    fn wait_pending(&self, seq: u16) -> Result<u32> {
        self.wait_pending_until(seq, Instant::now() + REQUEST_TIMEOUT)
    }

    fn wait_pending_until(&self, seq: u16, deadline: Instant) -> Result<u32> {
        loop {
            if let Some((status, value)) = {
                let state = self.state.borrow();
                state
                    .pending
                    .get(&seq)
                    .and_then(|pending| pending.status.map(|status| (status, pending.value)))
            } {
                self.state.borrow_mut().pending.remove(&seq);
                if status != STATUS_OK {
                    return Err(Error::Platform {
                        operation: "ubus_request",
                        code: status,
                    });
                }
                return value.ok_or(Error::InvalidData("ubus response omitted object id"));
            }
            let now = Instant::now();
            if now >= deadline {
                self.state.borrow_mut().pending.remove(&seq);
                return Err(Error::Platform {
                    operation: "ubus_request",
                    code: STATUS_TIMEOUT,
                });
            }
            if let Err(error) =
                self.poll_once(deadline.duration_since(now).as_millis().min(250) as libc::c_int)
            {
                self.state.borrow_mut().pending.remove(&seq);
                return Err(error);
            }
        }
    }

    fn queue_pending_frame(
        &self,
        seq: u16,
        pending: PendingRequest,
        kind: u8,
        peer: u32,
        body: Vec<u8>,
    ) -> Result<()> {
        self.state.borrow_mut().pending.insert(seq, pending);
        if let Err(error) = self.queue_frame(kind, seq, peer, body) {
            self.state.borrow_mut().pending.remove(&seq);
            return Err(error);
        }
        Ok(())
    }

    fn queue_frame(&self, kind: u8, seq: u16, peer: u32, body: Vec<u8>) -> Result<()> {
        let frame = encode_frame(kind, seq, peer, &body)?;
        let mut state = self.state.borrow_mut();
        if state.stream.is_none() {
            return Err(Error::Platform {
                operation: "ubus_send",
                code: STATUS_CONNECTION_FAILED,
            });
        }
        if state.queued_bytes.saturating_add(frame.len()) > MAX_QUEUED_BYTES {
            return Err(Error::Platform {
                operation: "ubus_backpressure",
                code: libc::ENOBUFS,
            });
        }
        state.queued_bytes += frame.len();
        state.outbound.push_back(Outbound {
            bytes: frame,
            offset: 0,
        });
        drop(state);
        if let Err(error) = self.flush_writes() {
            self.mark_lost();
            return Err(error);
        }
        Ok(())
    }

    fn flush_writes(&self) -> Result<()> {
        let mut state = self.state.borrow_mut();
        let ConnectionState {
            stream,
            outbound,
            queued_bytes,
            ..
        } = &mut *state;
        let stream = stream.as_mut().ok_or(Error::Platform {
            operation: "ubus_send",
            code: STATUS_CONNECTION_FAILED,
        })?;
        while let Some(front) = outbound.front_mut() {
            match stream.write(&front.bytes[front.offset..]) {
                Ok(0) => {
                    return Err(Error::Platform {
                        operation: "ubus_send",
                        code: STATUS_CONNECTION_FAILED,
                    })
                }
                Ok(written) => {
                    front.offset += written;
                    *queued_bytes = queued_bytes.saturating_sub(written);
                    if front.offset == front.bytes.len() {
                        outbound.pop_front();
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error("ubus_send", error)),
            }
        }
        Ok(())
    }

    fn poll_once(&self, timeout: libc::c_int) -> Result<()> {
        let result = self.poll_once_inner(timeout);
        if result.is_err() {
            self.mark_lost();
        }
        result
    }

    fn poll_once_inner(&self, timeout: libc::c_int) -> Result<()> {
        if self.has_complete_frame()? {
            self.read_frames()?;
            return Ok(());
        }
        let (fd, wants_write) = {
            let state = self.state.borrow();
            let fd = state
                .stream
                .as_ref()
                .ok_or(Error::Platform {
                    operation: "ubus_poll",
                    code: STATUS_CONNECTION_FAILED,
                })?
                .as_raw_fd();
            (fd, !state.outbound.is_empty())
        };
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN
                | libc::POLLERR
                | libc::POLLHUP
                | if wants_write { libc::POLLOUT } else { 0 },
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, timeout) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(io_error("ubus_poll", error));
        }
        if result > 0 {
            self.handle_events(pollfd.revents)?;
        }
        Ok(())
    }

    fn handle_events(&self, events: libc::c_short) -> Result<()> {
        if events & libc::POLLOUT != 0 {
            self.flush_writes()?;
        }
        let yielded = if events & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            self.read_frames()?
        } else {
            false
        };
        if events & libc::POLLNVAL != 0
            || (events & (libc::POLLERR | libc::POLLHUP) != 0 && !yielded)
        {
            self.mark_lost();
        }
        Ok(())
    }

    fn has_complete_frame(&self) -> Result<bool> {
        let state = self.state.borrow();
        buffered_frame_len(&state).map(|length| length.is_some())
    }

    fn read_frames(&self) -> Result<bool> {
        let mut eof = false;
        let mut yielded = false;
        let mut bytes_read = 0usize;
        let mut frames_read = 0usize;
        let mut read_chunk = [0u8; READ_CHUNK_LEN];
        let mut frame = Vec::new();

        loop {
            while frames_read < MAX_READ_FRAMES_PER_BATCH {
                let copied = self.copy_next_frame(&mut frame)?;
                if !copied {
                    break;
                }
                self.dispatch_frame(&frame)?;
                frames_read += 1;
            }

            if frames_read == MAX_READ_FRAMES_PER_BATCH || bytes_read == MAX_READ_BYTES_PER_BATCH {
                yielded = true;
                break;
            }

            let read_limit = {
                let mut state = self.state.borrow_mut();
                compact_read_buffer(&mut state)?;
                let buffered = state.read_buffer.len();
                if buffered >= MAX_QUEUED_BYTES {
                    return Err(Error::InvalidData("ubus receive buffer exceeds limit"));
                }
                READ_CHUNK_LEN
                    .min(MAX_READ_BYTES_PER_BATCH - bytes_read)
                    .min(MAX_QUEUED_BYTES - buffered)
            };

            let read = {
                let mut state = self.state.borrow_mut();
                let ConnectionState {
                    stream,
                    read_buffer,
                    ..
                } = &mut *state;
                let stream = stream.as_mut().ok_or(Error::Platform {
                    operation: "ubus_receive",
                    code: STATUS_CONNECTION_FAILED,
                })?;
                match stream.read(&mut read_chunk[..read_limit]) {
                    Ok(0) => {
                        eof = true;
                        None
                    }
                    Ok(read) => {
                        read_buffer.extend_from_slice(&read_chunk[..read]);
                        Some(read)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(io_error("ubus_receive", error)),
                }
            };
            let Some(read) = read else { break };
            bytes_read += read;
        }

        if eof {
            self.mark_lost();
        }
        Ok(yielded)
    }

    fn copy_next_frame(&self, frame: &mut Vec<u8>) -> Result<bool> {
        let mut state = self.state.borrow_mut();
        let Some(total) = buffered_frame_len(&state)? else {
            return Ok(false);
        };
        let start = state.read_offset;
        frame.clear();
        frame.extend_from_slice(&state.read_buffer[start..start + total]);
        state.read_offset += total;
        Ok(true)
    }

    fn dispatch_frame(&self, frame: &[u8]) -> Result<()> {
        if frame.len() < MIN_FRAME_LEN || frame[0] != UBUS_VERSION {
            return Err(Error::InvalidData("invalid ubus frame"));
        }
        let kind = frame[1];
        let seq = u16::from_be_bytes(frame[2..4].try_into().unwrap());
        let peer = u32::from_be_bytes(frame[4..8].try_into().unwrap());
        let root = codec::parse_attr(&frame[8..])?;
        if root.id != 0 || root.raw_len + FRAME_HEADER_LEN != frame.len() {
            return Err(Error::InvalidData("invalid ubus root blob"));
        }
        match kind {
            UBUS_MSG_DATA => self.handle_data(seq, root.payload),
            UBUS_MSG_STATUS => self.handle_status(seq, root.payload),
            UBUS_MSG_INVOKE => self.handle_invoke(seq, peer, root.payload),
            _ => Ok(()),
        }
    }

    fn handle_data(&self, seq: u16, payload: &[u8]) -> Result<()> {
        let Some(value) = outer_u32(payload, UBUS_ATTR_OBJID)? else {
            return Ok(());
        };
        let mut state = self.state.borrow_mut();
        let Some(pending) = state.pending.get_mut(&seq) else {
            return Ok(());
        };
        pending.value = Some(value);
        if let Some(index) = pending.object_index {
            if let Some(object) = state.objects.get(index) {
                object.id.set(Some(value));
            }
        }
        Ok(())
    }

    fn handle_status(&self, seq: u16, payload: &[u8]) -> Result<()> {
        let status = outer_u32(payload, UBUS_ATTR_STATUS)?
            .ok_or(Error::InvalidData("ubus status omitted status code"))?
            as libc::c_int;
        if let Some(pending) = self.state.borrow_mut().pending.get_mut(&seq) {
            pending.status = Some(status);
        }
        Ok(())
    }

    fn handle_invoke(&self, seq: u16, peer: u32, payload: &[u8]) -> Result<()> {
        let object_id = outer_u32(payload, UBUS_ATTR_OBJID)?
            .ok_or(Error::InvalidData("ubus invoke omitted object id"))?;
        let method_name = outer_string(payload, UBUS_ATTR_METHOD)?
            .ok_or(Error::InvalidData("ubus invoke omitted method"))?;
        let no_reply = outer_payload(payload, UBUS_ATTR_NO_REPLY)?
            .and_then(|value| value.first().copied())
            .unwrap_or(0)
            != 0;
        let object = self
            .state
            .borrow()
            .objects
            .iter()
            .find(|object| object.id.get() == Some(object_id))
            .cloned();
        let Some(object) = object else {
            self.queue_status(seq, peer, object_id, 4)?;
            return Ok(());
        };
        let Some(method) = object
            .methods
            .iter()
            .find(|method| method.name == method_name)
        else {
            self.queue_status(seq, peer, object_id, 3)?;
            return Ok(());
        };
        let Some(data) = outer_payload(payload, UBUS_ATTR_DATA)? else {
            // ubusd forwards syntactically valid INVOKE messages without DATA.
            // libubus treats this as a request error and keeps the connection.
            self.queue_status(seq, peer, object_id, STATUS_INVALID_ARGUMENT)?;
            return Ok(());
        };
        let data = data.to_vec();
        self.dispatch_depth.set(self.dispatch_depth.get() + 1);
        struct DepthGuard<'a>(&'a Cell<usize>);
        impl Drop for DepthGuard<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() - 1);
            }
        }
        let _depth = DepthGuard(&self.dispatch_depth);
        let Some(mut handler) = method.handler.borrow_mut().take() else {
            if !no_reply {
                self.queue_status(seq, peer, object_id, STATUS_UNKNOWN_ERROR)?;
            }
            return Ok(());
        };
        let request = UbusRequest {
            connection: self
                .self_weak
                .upgrade()
                .ok_or(Error::InvalidData("ubus connection was dropped"))?,
            request: RequestMeta {
                seq,
                peer,
                object: object_id,
            },
            message: data,
            policies: &method.policies,
            _lifetime: PhantomData,
        };
        let status =
            catch_unwind(AssertUnwindSafe(|| handler(request))).unwrap_or(STATUS_UNKNOWN_ERROR);
        *method.handler.borrow_mut() = Some(handler);
        if !no_reply {
            self.queue_status(seq, peer, object_id, status)?;
        }
        Ok(())
    }

    fn queue_status(&self, seq: u16, peer: u32, object: u32, status: libc::c_int) -> Result<()> {
        let mut attrs = codec::encode_u32_attr(UBUS_ATTR_STATUS, status as u32)?;
        attrs.extend_from_slice(&codec::encode_u32_attr(UBUS_ATTR_OBJID, object)?);
        self.queue_frame(UBUS_MSG_STATUS, seq, peer, codec::encode_root(&attrs)?)
    }

    fn mark_lost(&self) {
        let notify = {
            let mut state = self.state.borrow_mut();
            state.stream.take();
            state.read_buffer.clear();
            state.read_offset = 0;
            state.outbound.clear();
            state.queued_bytes = 0;
            for pending in state.pending.values_mut() {
                pending.status = Some(STATUS_CONNECTION_FAILED);
            }
            for object in &state.objects {
                object.id.set(None);
                object.type_id.set(None);
            }
            !state.connection_lost_notified
        };
        if !notify {
            return;
        }
        self.state.borrow_mut().connection_lost_notified = true;
        let Some(mut handler) = self.connection_lost_handler.borrow_mut().take() else {
            return;
        };
        let _ = catch_unwind(AssertUnwindSafe(|| handler()));
        *self.connection_lost_handler.borrow_mut() = Some(handler);
    }
}

fn encode_object_registration(object: &ObjectInner) -> Result<Vec<u8>> {
    let mut attrs = codec::encode_string_attr(UBUS_ATTR_OBJPATH, &object.name)?;
    let mut signature = Vec::new();
    for method in &object.methods {
        let mut policies = Vec::new();
        for (name, kind) in &method.policies {
            policies.extend_from_slice(&codec::encode_blobmsg_field(
                codec::BLOBMSG_INT32,
                name,
                &u32::from(*kind).to_be_bytes(),
            )?);
        }
        signature.extend_from_slice(&codec::encode_blobmsg_field(
            codec::BLOBMSG_TABLE,
            &method.name,
            &policies,
        )?);
    }
    attrs.extend_from_slice(&codec::encode_attr(UBUS_ATTR_SIGNATURE, false, &signature)?);
    codec::encode_root(&attrs)
}

fn encode_frame(kind: u8, seq: u16, peer: u32, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > codec::MAX_MESSAGE_LEN {
        return Err(Error::InvalidData("ubus message exceeds limit"));
    }
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.push(UBUS_VERSION);
    frame.push(kind);
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&peer.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn buffered_frame_len(state: &ConnectionState) -> Result<Option<usize>> {
    if state.read_offset > state.read_buffer.len() {
        return Err(Error::InvalidData("invalid ubus receive cursor"));
    }
    let available = state.read_buffer.len() - state.read_offset;
    if available < MIN_FRAME_LEN {
        return Ok(None);
    }
    let header = state.read_offset + FRAME_HEADER_LEN;
    let raw_len = (u32::from_be_bytes(state.read_buffer[header..header + 4].try_into().unwrap())
        & 0x00ff_ffff) as usize;
    if raw_len < 4 || raw_len > codec::MAX_MESSAGE_LEN {
        return Err(Error::InvalidData("invalid ubus frame length"));
    }
    let total = FRAME_HEADER_LEN + raw_len;
    if available < total {
        Ok(None)
    } else {
        Ok(Some(total))
    }
}

fn compact_read_buffer(state: &mut ConnectionState) -> Result<()> {
    if state.read_offset > state.read_buffer.len() {
        return Err(Error::InvalidData("invalid ubus receive cursor"));
    }
    if state.read_offset == 0 {
        return Ok(());
    }
    let unread = state.read_buffer.len() - state.read_offset;
    if unread != 0 {
        state.read_buffer.copy_within(state.read_offset.., 0);
    }
    state.read_buffer.truncate(unread);
    state.read_offset = 0;
    Ok(())
}

fn io_error(operation: &'static str, error: std::io::Error) -> Error {
    Error::Platform {
        operation,
        code: error.raw_os_error().unwrap_or(libc::EIO),
    }
}

fn outer_attrs(payload: &[u8]) -> Result<Vec<codec::Attr<'_>>> {
    codec::parse_attr_list(payload)
}

fn outer_payload<'a>(payload: &'a [u8], id: u8) -> Result<Option<&'a [u8]>> {
    let mut found = None;
    for attr in outer_attrs(payload)? {
        if attr.id != id {
            continue;
        }
        if found.is_some() {
            return Err(Error::InvalidData("duplicate ubus attribute"));
        }
        found = Some(attr.payload);
    }
    Ok(found)
}

fn outer_u32(payload: &[u8], id: u8) -> Result<Option<u32>> {
    outer_payload(payload, id)?
        .map(|value| {
            if value.len() != 4 {
                return Err(Error::InvalidData("invalid ubus integer attribute"));
            }
            Ok(u32::from_be_bytes(value.try_into().unwrap()))
        })
        .transpose()
}

fn outer_string(payload: &[u8], id: u8) -> Result<Option<String>> {
    outer_payload(payload, id)?
        .map(|value| {
            let value = value
                .strip_suffix(&[0])
                .ok_or(Error::InvalidData("unterminated ubus string"))?;
            if value.contains(&0) {
                return Err(Error::InvalidData("ubus string contains an interior NUL"));
            }
            std::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_| Error::InvalidData("ubus string is not UTF-8"))
        })
        .transpose()
}

pub(crate) fn poll_connections(timeout: libc::c_int) -> Result<()> {
    let connections = CONNECTIONS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retain(|connection| connection.strong_count() > 0);
        registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|connection| {
                let state = connection.state.borrow();
                state.attached && state.stream.is_some()
            })
            .collect::<Vec<_>>()
    });
    let mut handled_buffered = false;
    for connection in &connections {
        match connection.has_complete_frame() {
            Ok(true) => {
                handled_buffered = true;
                if connection.read_frames().is_err() {
                    connection.mark_lost();
                }
            }
            Ok(false) => {}
            Err(_) => {
                handled_buffered = true;
                connection.mark_lost();
            }
        }
    }
    if handled_buffered {
        return Ok(());
    }
    if connections.is_empty() {
        if timeout > 0 {
            unsafe { libc::poll(core::ptr::null_mut(), 0, timeout) };
        }
        return Ok(());
    }
    let mut descriptors = connections
        .iter()
        .map(|connection| {
            let state = connection.state.borrow();
            libc::pollfd {
                fd: state.stream.as_ref().unwrap().as_raw_fd(),
                events: libc::POLLIN
                    | libc::POLLERR
                    | libc::POLLHUP
                    | if state.outbound.is_empty() {
                        0
                    } else {
                        libc::POLLOUT
                    },
                revents: 0,
            }
        })
        .collect::<Vec<_>>();
    let result = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(io_error("ubus_poll", error));
    }
    for (connection, descriptor) in connections.iter().zip(descriptors) {
        if descriptor.revents == 0 {
            continue;
        }
        if connection.handle_events(descriptor.revents).is_err() {
            connection.mark_lost();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::mpsc;

    fn decode_hex(fixture: &str) -> Vec<u8> {
        let compact = fixture
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        assert_eq!(compact.len() % 2, 0, "hex fixture must contain byte pairs");
        compact
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("invalid hex fixture digit"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn test_connection(stream: Option<UnixStream>) -> Rc<ConnectionInner> {
        if let Some(stream) = &stream {
            stream.set_nonblocking(true).unwrap();
        }
        Rc::new_cyclic(|self_weak| ConnectionInner {
            path: PathBuf::from("/test/ubus.sock"),
            self_weak: self_weak.clone(),
            state: RefCell::new(ConnectionState {
                stream,
                read_buffer: Vec::new(),
                read_offset: 0,
                outbound: VecDeque::new(),
                queued_bytes: 0,
                objects: Vec::new(),
                pending: HashMap::new(),
                next_seq: 0,
                local_id: 2,
                attached: false,
                registered_in_loop: false,
                connection_lost_notified: false,
            }),
            connection_lost_handler: RefCell::new(None),
            dispatch_depth: Cell::new(0),
            _not_send_or_sync: PhantomData,
        })
    }

    fn install_counting_object(connection: &Rc<ConnectionInner>) -> Rc<Cell<usize>> {
        let calls = Rc::new(Cell::new(0));
        let seen = Rc::clone(&calls);
        let object = Rc::new(ObjectInner::from(
            UbusObject::new(
                "lanspeed",
                vec![UbusMethod::new("health", move |_| {
                    seen.set(seen.get() + 1);
                    STATUS_OK
                })
                .unwrap()],
            )
            .unwrap(),
        ));
        object.id.set(Some(41));
        connection.state.borrow_mut().objects.push(object);
        calls
    }

    fn no_reply_invoke_frame(data_len: usize) -> Vec<u8> {
        let mut payload = codec::encode_u32_attr(UBUS_ATTR_OBJID, 41).unwrap();
        payload.extend_from_slice(&codec::encode_string_attr(UBUS_ATTR_METHOD, "health").unwrap());
        payload.extend_from_slice(
            &codec::encode_attr(UBUS_ATTR_DATA, false, &vec![0; data_len]).unwrap(),
        );
        payload.extend_from_slice(&codec::encode_attr(UBUS_ATTR_NO_REPLY, false, &[1]).unwrap());
        encode_frame(
            UBUS_MSG_INVOKE,
            7,
            99,
            &codec::encode_root(&payload).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn add_object_frame_matches_libubus_golden_fixture() {
        let status = UbusMethod::new("status", |_| STATUS_OK).unwrap();
        let clients = UbusMethod::new("client_connections", |_| STATUS_OK)
            .unwrap()
            .with_string_policy("identity_key")
            .unwrap();
        let object =
            ObjectInner::from(UbusObject::new("lanspeed.test", vec![status, clients]).unwrap());
        let body = encode_object_registration(&object).unwrap();
        let actual = encode_frame(UBUS_MSG_ADD_OBJECT, 1, 0, &body).unwrap();
        let expected = decode_hex(include_str!("../tests/fixtures/ubus-add-object.hex"));
        assert_eq!(actual, expected);
    }

    #[test]
    fn outer_attribute_parser_rejects_duplicates() {
        let field = codec::encode_u32_attr(UBUS_ATTR_OBJID, 7).unwrap();
        let mut duplicate = field.clone();
        duplicate.extend_from_slice(&field);
        assert!(outer_u32(&duplicate, UBUS_ATTR_OBJID).is_err());
    }

    #[test]
    fn backpressure_rejects_frame_without_queuing_or_leaking_pending_request() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        connection.state.borrow_mut().queued_bytes = MAX_QUEUED_BYTES;
        let outbound_before = connection.state.borrow().outbound.len();
        let body = codec::encode_root(&[]).unwrap();

        let error = connection
            .queue_pending_frame(17, PendingRequest::default(), UBUS_MSG_LOOKUP, 0, body)
            .unwrap_err();

        assert_eq!(
            error,
            Error::Platform {
                operation: "ubus_backpressure",
                code: libc::ENOBUFS,
            }
        );
        let state = connection.state.borrow();
        assert_eq!(state.queued_bytes, MAX_QUEUED_BYTES);
        assert_eq!(state.outbound.len(), outbound_before);
        assert!(!state.pending.contains_key(&17));
    }

    #[test]
    fn disconnected_enqueue_does_not_leave_pending_request() {
        let connection = test_connection(None);
        let body = codec::encode_root(&[]).unwrap();
        let error = connection
            .queue_pending_frame(23, PendingRequest::default(), UBUS_MSG_LOOKUP, 0, body)
            .unwrap_err();
        assert_eq!(
            error,
            Error::Platform {
                operation: "ubus_send",
                code: STATUS_CONNECTION_FAILED,
            }
        );
        assert!(connection.state.borrow().pending.is_empty());
    }

    #[test]
    fn request_timeout_removes_pending_request() {
        let connection = test_connection(None);
        connection
            .state
            .borrow_mut()
            .pending
            .insert(29, PendingRequest::default());
        let error = connection
            .wait_pending_until(29, Instant::now())
            .unwrap_err();
        assert_eq!(
            error,
            Error::Platform {
                operation: "ubus_request",
                code: STATUS_TIMEOUT,
            }
        );
        assert!(!connection.state.borrow().pending.contains_key(&29));
    }

    #[test]
    fn malformed_wire_frame_closes_connection_and_notifies_loss_once() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        let notifications = Rc::new(Cell::new(0));
        let seen = Rc::clone(&notifications);
        *connection.connection_lost_handler.borrow_mut() = Some(Box::new(move || {
            seen.set(seen.get() + 1);
        }));

        peer.write_all(&[UBUS_VERSION, UBUS_MSG_DATA, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3])
            .unwrap();

        assert!(connection.poll_once(100).is_err());
        assert!(connection.state.borrow().stream.is_none());
        assert_eq!(notifications.get(), 1);
        connection.mark_lost();
        assert_eq!(notifications.get(), 1);
    }

    #[test]
    fn fragmented_frame_is_retained_until_complete() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        let calls = install_counting_object(&connection);
        let frame = no_reply_invoke_frame(0);
        let fragments = [1, MIN_FRAME_LEN - 1, frame.len() - 1, frame.len()];
        let mut start = 0;

        for end in fragments {
            peer.write_all(&frame[start..end]).unwrap();
            connection.read_frames().unwrap();
            start = end;

            if end != frame.len() {
                assert_eq!(calls.get(), 0);
                let state = connection.state.borrow();
                assert_eq!(state.read_offset, 0);
                assert_eq!(state.read_buffer, frame[..end]);
                assert!(state.stream.is_some());
            }
        }

        assert_eq!(calls.get(), 1);
        let state = connection.state.borrow();
        assert_eq!(state.read_offset, 0);
        assert!(state.read_buffer.is_empty());
        assert!(state.stream.is_some());
    }

    #[test]
    fn large_frame_crosses_read_byte_budget_without_disconnect() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        let calls = install_counting_object(&connection);
        let frame = no_reply_invoke_frame(MAX_READ_BYTES_PER_BATCH * 2);
        assert!(frame.len() > MAX_READ_BYTES_PER_BATCH * 2);
        let (written_tx, written_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            peer.write_all(&frame).unwrap();
            written_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        let deadline = Instant::now() + Duration::from_secs(10);

        while connection.state.borrow().read_buffer.is_empty() {
            assert!(Instant::now() < deadline, "large-frame read timed out");
            connection.poll_once(100).unwrap();
        }
        assert_eq!(calls.get(), 0);
        assert!(connection.state.borrow().stream.is_some());

        while calls.get() == 0 {
            assert!(Instant::now() < deadline, "large-frame dispatch timed out");
            connection.poll_once(100).unwrap();
        }

        written_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(connection.state.borrow().stream.is_some());
        release_tx.send(()).unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn frame_budget_yields_and_buffered_work_runs_without_new_readiness() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        let calls = install_counting_object(&connection);
        let frame = no_reply_invoke_frame(0);
        peer.write_all(&frame.repeat(MAX_READ_FRAMES_PER_BATCH + 1))
            .unwrap();

        connection.read_frames().unwrap();

        assert_eq!(calls.get(), MAX_READ_FRAMES_PER_BATCH);
        assert!(connection.has_complete_frame().unwrap());
        {
            let state = connection.state.borrow();
            assert_eq!(state.read_buffer.len() - state.read_offset, frame.len());
            assert_eq!(state.queued_bytes, 0);
            assert!(state.outbound.is_empty());
            assert!(state.stream.is_some());
        }

        connection.poll_once_inner(0).unwrap();

        assert_eq!(calls.get(), MAX_READ_FRAMES_PER_BATCH + 1);
        let state = connection.state.borrow();
        assert_eq!(state.read_offset, 0);
        assert!(state.read_buffer.is_empty());
        assert!(state.stream.is_some());
    }

    #[test]
    fn continuous_small_frames_exceed_receive_limit_without_false_disconnect() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        let calls = install_counting_object(&connection);
        let frame = no_reply_invoke_frame(192);
        let frame_count = MAX_QUEUED_BYTES / frame.len() + MAX_READ_FRAMES_PER_BATCH;
        let wire = frame.repeat(frame_count);
        assert!(wire.len() > MAX_QUEUED_BYTES);
        let (written_tx, written_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            peer.write_all(&wire).unwrap();
            written_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        let deadline = Instant::now() + Duration::from_secs(10);

        while calls.get() < frame_count {
            assert!(Instant::now() < deadline, "small-frame flood timed out");
            connection.poll_once(100).unwrap();
            assert!(
                connection.state.borrow().stream.is_some(),
                "valid traffic must not trip the receive-buffer limit"
            );
        }

        written_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(calls.get(), frame_count);
        {
            let state = connection.state.borrow();
            assert_eq!(state.read_offset, 0);
            assert!(state.read_buffer.is_empty());
            assert!(state.stream.is_some());
        }
        release_tx.send(()).unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn receive_limit_ignores_consumed_prefix() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        let calls = install_counting_object(&connection);
        let frame = no_reply_invoke_frame(0);
        {
            let mut state = connection.state.borrow_mut();
            state.read_buffer.resize(MAX_QUEUED_BYTES, 0);
            state.read_offset = state.read_buffer.len();
        }
        peer.write_all(&frame).unwrap();

        connection.read_frames().unwrap();

        assert_eq!(calls.get(), 1);
        let state = connection.state.borrow();
        assert_eq!(state.read_offset, 0);
        assert!(state.read_buffer.is_empty());
        assert!(state.stream.is_some());
    }

    #[test]
    fn hup_after_frame_budget_drains_buffer_before_notifying_loss() {
        let (stream, peer) = UnixStream::pair().unwrap();
        let connection = test_connection(Some(stream));
        let calls = install_counting_object(&connection);
        let notifications = Rc::new(Cell::new(0));
        let seen = Rc::clone(&notifications);
        *connection.connection_lost_handler.borrow_mut() = Some(Box::new(move || {
            seen.set(seen.get() + 1);
        }));
        let frame = no_reply_invoke_frame(0);
        connection.state.borrow_mut().read_buffer = frame.repeat(MAX_READ_FRAMES_PER_BATCH + 1);
        drop(peer);

        connection.handle_events(libc::POLLHUP).unwrap();

        assert_eq!(calls.get(), MAX_READ_FRAMES_PER_BATCH);
        assert_eq!(notifications.get(), 0);
        assert!(connection.state.borrow().stream.is_some());

        connection.poll_once_inner(0).unwrap();

        assert_eq!(calls.get(), MAX_READ_FRAMES_PER_BATCH + 1);
        assert_eq!(notifications.get(), 1);
        assert!(connection.state.borrow().stream.is_none());
    }

    #[test]
    fn invoke_without_data_returns_invalid_argument_without_dropping_connection() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let connection = test_connection(Some(stream));
        let calls = Rc::new(Cell::new(0));
        let calls_seen = Rc::clone(&calls);
        let object = Rc::new(ObjectInner::from(
            UbusObject::new(
                "lanspeed",
                vec![UbusMethod::new("health", move |_| {
                    calls_seen.set(calls_seen.get() + 1);
                    STATUS_OK
                })
                .unwrap()],
            )
            .unwrap(),
        ));
        object.id.set(Some(41));
        connection.state.borrow_mut().objects.push(object);

        let mut payload = codec::encode_u32_attr(UBUS_ATTR_OBJID, 41).unwrap();
        payload.extend_from_slice(&codec::encode_string_attr(UBUS_ATTR_METHOD, "health").unwrap());
        connection.handle_invoke(7, 99, &payload).unwrap();

        let mut header = [0u8; 12];
        peer.read_exact(&mut header).unwrap();
        let raw_len =
            (u32::from_be_bytes(header[8..12].try_into().unwrap()) & 0x00ff_ffff) as usize;
        let mut frame = header.to_vec();
        frame.resize(8 + raw_len, 0);
        peer.read_exact(&mut frame[12..]).unwrap();
        let root = codec::parse_attr(&frame[8..]).unwrap();

        assert_eq!(header[1], UBUS_MSG_STATUS);
        assert_eq!(u16::from_be_bytes(header[2..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_be_bytes(header[4..8].try_into().unwrap()), 99);
        assert_eq!(
            outer_u32(root.payload, UBUS_ATTR_STATUS).unwrap(),
            Some(STATUS_INVALID_ARGUMENT as u32)
        );
        assert_eq!(calls.get(), 0);
        assert!(connection.state.borrow().stream.is_some());
    }
}
