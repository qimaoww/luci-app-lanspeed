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
