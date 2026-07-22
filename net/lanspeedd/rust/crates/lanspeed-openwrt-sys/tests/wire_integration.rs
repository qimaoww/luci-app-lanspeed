use lanspeed_openwrt_sys::{
    UbusConnection, UbusMethod, UbusObject, UloopGuard, STATUS_INVALID_ARGUMENT, STATUS_OK,
};
use std::{
    cell::Cell,
    fs,
    process::{Child, Command, Stdio},
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

fn spawn_ubusd(
    loader: &std::path::Path,
    library_path: &str,
    rootfs: &std::path::Path,
    socket: &std::path::Path,
) -> Child {
    Command::new(loader)
        .args(["--library-path", library_path])
        .arg(rootfs.join("sbin/ubusd"))
        .args(["-s", socket.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn pure_rust_server_registers_and_replies_to_real_ubusd() {
    let Some(rootfs) = std::env::var_os("LANSPEED_OPENWRT_ROOTFS").map(std::path::PathBuf::from)
    else {
        eprintln!("skipped: LANSPEED_OPENWRT_ROOTFS is not set");
        return;
    };
    let loader = rootfs.join("lib/libc.so");
    let library_path = format!(
        "{}:{}",
        rootfs.join("lib").display(),
        rootfs.join("usr/lib").display()
    );
    let directory = std::env::temp_dir().join(format!("lanspeed-ubus-wire-{}", std::process::id()));
    let socket = directory.join("ubus.sock");
    fs::create_dir_all(&directory).unwrap();
    let mut daemon = spawn_ubusd(&loader, &library_path, &rootfs, &socket);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "ubusd did not create its socket");

    let method = UbusMethod::new("echo", |mut request| {
        let Some(value) = request.string("identity_key").ok().flatten() else {
            return STATUS_INVALID_ARGUMENT;
        };
        request
            .reply_json(&format!(
                r#"{{"ok":true,"identity_key":{}}}"#,
                serde_json::to_string(&value).unwrap()
            ))
            .unwrap();
        UloopGuard::request_stop();
        STATUS_OK
    })
    .unwrap()
    .with_string_policy("identity_key")
    .unwrap();
    let mut connection = UbusConnection::connect(Some(socket.to_str().unwrap())).unwrap();
    connection.attach_uloop().unwrap();
    connection
        .register_object(UbusObject::new("lanspeed.test", vec![method]).unwrap())
        .unwrap();

    let lost = Rc::new(Cell::new(false));
    let lost_in_handler = Rc::clone(&lost);
    connection.set_connection_lost_handler(move || {
        lost_in_handler.set(true);
        UloopGuard::request_stop();
    });
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    let mut loss_loop = UloopGuard::init().unwrap();
    loss_loop.run().unwrap();
    drop(loss_loop);
    assert!(lost.get(), "connection loss callback did not run");

    daemon = spawn_ubusd(&loader, &library_path, &rootfs, &socket);
    thread::sleep(Duration::from_millis(50));
    connection
        .reconnect(Some(socket.to_str().unwrap()))
        .unwrap();
    connection.reregister_objects().unwrap();

    // The command blocks until the event loop handles it, so launch it in a
    // helper thread while the main thread retains ownership of the Rc runtime.
    let client_loader = loader.clone();
    let client_rootfs = rootfs.clone();
    let client_socket = socket.clone();
    let client_library_path = library_path.clone();
    let client_thread = thread::spawn(move || {
        Command::new(client_loader)
            .args(["--library-path", &client_library_path])
            .arg(client_rootfs.join("bin/ubus"))
            .args([
                "-s",
                client_socket.to_str().unwrap(),
                "call",
                "lanspeed.test",
                "echo",
                r#"{"identity_key":"client@lan"}"#,
            ])
            .output()
            .unwrap()
    });
    let mut event_loop = UloopGuard::init().unwrap();
    event_loop.run().unwrap();
    let output = client_thread.join().unwrap();
    assert!(
        output.status.success(),
        "ubus call failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response,
        serde_json::json!({"ok": true, "identity_key": "client@lan"})
    );

    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = fs::remove_dir_all(directory);
}
