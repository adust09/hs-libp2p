use super::*;

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_listener_new(ip: *const c_char, port: u16) -> *mut HsWebRtcListener {
    let result = (|| -> Result<HsWebRtcListener, String> {
        let address = SocketAddr::new(parse_ip(ip)?, port);
        let socket = UdpSocket::bind(address).map_err(|err| err.to_string())?;
        socket
            .set_nonblocking(true)
            .map_err(|err| err.to_string())?;
        let local_addr = socket.local_addr().map_err(|err| err.to_string())?;
        let provider = crypto_provider();
        let certificate = generate_certificate(&provider)?;
        let mut rtc = rtc_config(provider.clone(), certificate.clone()).build(Instant::now());
        let fingerprint = rtc.direct_api().local_dtls_fingerprint().bytes.clone();
        let shared = Arc::new(ListenerShared {
            state: Mutex::new(ListenerState {
                incoming: VecDeque::new(),
                closed: false,
                error: None,
            }),
            ready: Condvar::new(),
            shutdown: AtomicBool::new(false),
            fingerprint,
            local_addr,
        });
        let worker_shared = shared.clone();
        let worker =
            thread::spawn(move || listener_loop(socket, worker_shared, provider, certificate));
        Ok(HsWebRtcListener {
            shared,
            worker: Some(worker),
        })
    })();
    match result {
        Ok(listener) => Box::into_raw(Box::new(listener)),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_listener_port(listener: *const HsWebRtcListener) -> u16 {
    if listener.is_null() {
        return 0;
    }
    unsafe { (&(*listener).shared).local_addr.port() }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_listener_fingerprint(
    listener: *const HsWebRtcListener,
    output: *mut u8,
    length: usize,
) -> i32 {
    if listener.is_null() || output.is_null() {
        set_error("null listener fingerprint argument");
        return -1;
    }
    let fingerprint = unsafe { &(&(*listener).shared).fingerprint };
    if length < fingerprint.len() {
        set_error("fingerprint output buffer is too small");
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(fingerprint.as_ptr(), output, fingerprint.len());
    }
    fingerprint.len() as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_listener_accept(
    listener: *const HsWebRtcListener,
    status: *mut i32,
) -> *mut HsWebRtcConnection {
    if listener.is_null() || status.is_null() {
        set_error("null listener accept argument");
        return ptr::null_mut();
    }
    let shared = unsafe { &(*listener).shared };
    let mut state = shared.state.lock().unwrap();
    if let Some(connection) = state.incoming.pop_front() {
        unsafe { *status = 0 };
        return Box::into_raw(Box::new(HsWebRtcConnection { shared: connection }));
    }
    if let Some(err) = &state.error {
        set_error(err);
        unsafe { *status = -1 };
        return ptr::null_mut();
    }
    if state.closed {
        set_error("WebRTC listener is closed");
        unsafe { *status = -1 };
        return ptr::null_mut();
    }
    unsafe { *status = 1 };
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_listener_close(listener: *mut HsWebRtcListener) {
    if listener.is_null() {
        return;
    }
    let mut listener = unsafe { Box::from_raw(listener) };
    listener.shared.shutdown.store(true, Ordering::Relaxed);
    if let Some(worker) = listener.worker.take() {
        let _ = worker.join();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_dial(
    ip: *const c_char,
    port: u16,
    fingerprint: *const u8,
    fingerprint_len: usize,
    version: u8,
) -> *mut HsWebRtcConnection {
    let result = dial_connection(ip, port, fingerprint, fingerprint_len, version);
    match result {
        Ok(shared) => Box::into_raw(Box::new(HsWebRtcConnection { shared })),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

fn dial_connection(
    ip: *const c_char,
    port: u16,
    fingerprint: *const u8,
    fingerprint_len: usize,
    version: u8,
) -> Result<Arc<SharedConnection>, String> {
    if fingerprint.is_null() || fingerprint_len != 32 {
        return Err("WebRTC Direct requires a 32-byte SHA-256 fingerprint".into());
    }
    let remote_fingerprint =
        unsafe { slice::from_raw_parts(fingerprint, fingerprint_len) }.to_vec();
    let remote_addr = SocketAddr::new(parse_ip(ip)?, port);
    let socket = open_dial_socket(remote_addr)?;
    let local_addr = socket.local_addr().map_err(|err| err.to_string())?;
    let runtime = configure_dial(local_addr, remote_addr, remote_fingerprint, version)?;
    let shared = runtime.shared.clone();
    thread::spawn(move || dial_loop(socket, local_addr, runtime));
    if let Err(err) = await_dial(&shared) {
        let _ = shared.command.send(Command::Close);
        return Err(err);
    }
    Ok(shared)
}

fn open_dial_socket(remote_addr: SocketAddr) -> Result<UdpSocket, String> {
    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr).map_err(|err| err.to_string())?;
    socket.connect(remote_addr).map_err(|err| err.to_string())?;
    socket
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;
    Ok(socket)
}

fn dial_loop(socket: UdpSocket, local_addr: SocketAddr, mut runtime: ConnectionRuntime) {
    let mut buffer = vec![0u8; MAX_PACKET_SIZE];
    loop {
        if let Err(err) = receive_dial_packets(&socket, local_addr, &mut runtime, &mut buffer) {
            runtime.shared.fail(err);
            return;
        }
        match runtime.tick(&socket, Instant::now()) {
            Ok(true) => thread::sleep(Duration::from_millis(2)),
            Ok(false) => {
                runtime.shared.fail("WebRTC connection closed");
                return;
            }
            Err(err) => {
                runtime.shared.fail(err);
                return;
            }
        }
    }
}

fn receive_dial_packets(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    runtime: &mut ConnectionRuntime,
    buffer: &mut [u8],
) -> Result<(), String> {
    loop {
        match socket.recv_from(buffer) {
            Ok((size, source)) => {
                if let Ok(receive) =
                    Receive::new(Protocol::Udp, source, local_addr, &buffer[..size])
                {
                    runtime.receive(receive)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) => return Err(err.to_string()),
        }
    }
}

fn await_dial(shared: &SharedConnection) -> Result<(), String> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut state = shared.state.lock().unwrap();
    while !state.ready && state.error.is_none() && !state.closed {
        let now = Instant::now();
        if now >= deadline {
            return Err("WebRTC Direct dial timed out".into());
        }
        let (next, _) = shared.ready.wait_timeout(state, deadline - now).unwrap();
        state = next;
    }
    match (&state.error, state.ready) {
        (Some(err), _) => Err(err.clone()),
        (_, true) => Ok(()),
        _ => Err("WebRTC Direct dial closed before authentication".into()),
    }
}

fn connection_fingerprint(
    connection: *const HsWebRtcConnection,
    output: *mut u8,
    length: usize,
    remote: bool,
) -> i32 {
    if connection.is_null() || output.is_null() {
        set_error("null connection fingerprint argument");
        return -1;
    }
    let state = unsafe { (&(*connection).shared).state.lock().unwrap() };
    let fingerprint = if remote {
        &state.remote_fingerprint
    } else {
        &state.local_fingerprint
    };
    if length < fingerprint.len() {
        set_error("fingerprint output buffer is too small");
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(fingerprint.as_ptr(), output, fingerprint.len());
    }
    fingerprint.len() as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_local_fingerprint(
    connection: *const HsWebRtcConnection,
    output: *mut u8,
    length: usize,
) -> i32 {
    connection_fingerprint(connection, output, length, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_remote_fingerprint(
    connection: *const HsWebRtcConnection,
    output: *mut u8,
    length: usize,
) -> i32 {
    connection_fingerprint(connection, output, length, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_ip(
    connection: *const HsWebRtcConnection,
    remote: i32,
    output: *mut c_char,
    length: usize,
) -> i32 {
    if connection.is_null() || output.is_null() {
        set_error("null connection address argument");
        return -1;
    }
    let shared = unsafe { &(*connection).shared };
    let address = if remote != 0 {
        shared.remote_addr
    } else {
        shared.local_addr
    };
    let text = address.ip().to_string();
    if length <= text.len() {
        set_error("connection address output buffer is too small");
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(text.as_ptr(), output.cast(), text.len());
        *output.add(text.len()) = 0;
    }
    text.len() as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_port(
    connection: *const HsWebRtcConnection,
    remote: i32,
) -> u16 {
    if connection.is_null() {
        return 0;
    }
    let shared = unsafe { &(*connection).shared };
    if remote != 0 {
        shared.remote_addr.port()
    } else {
        shared.local_addr.port()
    }
}

fn channel_handle(connection: Arc<SharedConnection>, token: u64) -> *mut HsWebRtcChannel {
    Box::into_raw(Box::new(HsWebRtcChannel { connection, token }))
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_noise_channel(
    connection: *const HsWebRtcConnection,
) -> *mut HsWebRtcChannel {
    if connection.is_null() {
        set_error("connection is null");
        return ptr::null_mut();
    }
    channel_handle(unsafe { (*connection).shared.clone() }, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_open_channel(
    connection: *const HsWebRtcConnection,
) -> *mut HsWebRtcChannel {
    if connection.is_null() {
        set_error("connection is null");
        return ptr::null_mut();
    }
    let shared = unsafe { (*connection).shared.clone() };
    match open_channel(&shared) {
        Ok(token) => channel_handle(shared, token),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

fn open_channel(shared: &SharedConnection) -> Result<u64, String> {
    let (tx, rx) = mpsc::channel();
    shared
        .command
        .send(Command::OpenChannel { response: tx })
        .map_err(|_| "WebRTC connection worker stopped")?;
    let token = rx
        .recv()
        .map_err(|_| "WebRTC connection worker stopped")??;
    let channel = shared
        .state
        .lock()
        .unwrap()
        .channels
        .get(&token)
        .cloned()
        .ok_or("WebRTC connection lost the opened data channel")?;
    wait_for_channel_open(&channel)?;
    Ok(token)
}

fn wait_for_channel_open(channel: &SharedChannel) -> Result<(), String> {
    let mut state = channel.state.lock().unwrap();
    while !state.open && !state.closed && state.error.is_none() {
        state = channel.ready.wait(state).unwrap();
    }
    if state.open {
        Ok(())
    } else {
        Err(state
            .error
            .clone()
            .unwrap_or_else(|| "WebRTC data channel closed before opening".into()))
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_accept_channel(
    connection: *const HsWebRtcConnection,
) -> *mut HsWebRtcChannel {
    if connection.is_null() {
        set_error("connection is null");
        return ptr::null_mut();
    }
    let shared = unsafe { (*connection).shared.clone() };
    let mut state = shared.state.lock().unwrap();
    loop {
        if let Some(token) = state.incoming.pop_front() {
            return channel_handle(shared.clone(), token);
        }
        if let Some(err) = &state.error {
            set_error(err);
            return ptr::null_mut();
        }
        if state.closed {
            set_error("WebRTC connection is closed");
            return ptr::null_mut();
        }
        state = shared.ready.wait(state).unwrap();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_channel_send(
    channel: *const HsWebRtcChannel,
    data: *const u8,
    length: usize,
) -> i32 {
    if channel.is_null() || (data.is_null() && length != 0) {
        set_error("null channel send argument");
        return -1;
    }
    let channel = unsafe { &*channel };
    let bytes = if length == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(data, length) }.to_vec()
    };
    let (tx, rx) = mpsc::channel();
    if channel
        .connection
        .command
        .send(Command::Send {
            token: channel.token,
            data: bytes,
            response: tx,
        })
        .is_err()
    {
        set_error("WebRTC connection worker stopped");
        return -1;
    }
    match rx.recv() {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => {
            set_error(err);
            -1
        }
        Err(_) => {
            set_error("WebRTC connection worker stopped");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_channel_recv(
    channel: *const HsWebRtcChannel,
    output: *mut *mut u8,
    length: *mut usize,
) -> i32 {
    if channel.is_null() || output.is_null() || length.is_null() {
        set_error("null channel receive argument");
        return -1;
    }
    let channel = unsafe { &*channel };
    let shared_channel = {
        let state = channel.connection.state.lock().unwrap();
        match state.channels.get(&channel.token).cloned() {
            Some(value) => value,
            None => {
                set_error("unknown WebRTC data channel");
                return -1;
            }
        }
    };
    let mut state = shared_channel.state.lock().unwrap();
    loop {
        if let Some(bytes) = state.messages.pop_front() {
            let mut boxed = bytes.into_boxed_slice();
            unsafe {
                *length = boxed.len();
                *output = boxed.as_mut_ptr();
            }
            std::mem::forget(boxed);
            return 0;
        }
        if let Some(err) = &state.error {
            set_error(err);
            return -1;
        }
        if state.closed {
            unsafe {
                *output = ptr::null_mut();
                *length = 0;
            }
            return 1;
        }
        state = shared_channel.ready.wait(state).unwrap();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_bytes_free(data: *mut u8, length: usize) {
    if data.is_null() {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(data, length, length));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_channel_close(channel: *mut HsWebRtcChannel) {
    if channel.is_null() {
        return;
    }
    let channel = unsafe { Box::from_raw(channel) };
    let _ = channel.connection.command.send(Command::CloseChannel {
        token: channel.token,
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_close(connection: *mut HsWebRtcConnection) {
    if connection.is_null() {
        return;
    }
    let connection = unsafe { Box::from_raw(connection) };
    let _ = connection.shared.command.send(Command::Close);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connects_v2_and_exchanges_noise_channel_data() {
        roundtrip("127.0.0.1", 2);
    }

    #[test]
    fn connects_v1_and_exchanges_noise_channel_data() {
        roundtrip("127.0.0.1", 1);
    }

    #[test]
    fn connects_to_wildcard_listener() {
        roundtrip("0.0.0.0", 1);
    }

    #[test]
    fn ignores_non_binding_stun_messages() {
        let mut packet = binding_request("libp2p+webrtc+v1/abcd:abcd");
        packet[1] = 0x11;
        assert!(parse_username(&packet).is_none());
    }

    fn binding_request(username: &str) -> Vec<u8> {
        let padded_length = (username.len() + 3) & !3;
        let message_length = 4 + padded_length;
        let mut packet = vec![0u8; 20 + message_length];
        packet[1] = 0x01;
        packet[2..4].copy_from_slice(&(message_length as u16).to_be_bytes());
        packet[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        packet[20..22].copy_from_slice(&0x0006u16.to_be_bytes());
        packet[22..24].copy_from_slice(&(username.len() as u16).to_be_bytes());
        packet[24..24 + username.len()].copy_from_slice(username.as_bytes());
        packet
    }

    fn roundtrip(listener_ip: &str, version: u8) {
        let bind_ip = CString::new(listener_ip).unwrap();
        let dial_ip = CString::new("127.0.0.1").unwrap();
        let listener = hs_webrtc_listener_new(bind_ip.as_ptr(), 0);
        assert!(!listener.is_null());
        let port = hs_webrtc_listener_port(listener);
        let mut fingerprint = [0u8; 32];
        assert_eq!(
            hs_webrtc_listener_fingerprint(listener, fingerprint.as_mut_ptr(), fingerprint.len()),
            32
        );

        let listener_address = listener as usize;
        let accept = thread::spawn(move || accept_connection(listener_address));
        let client = hs_webrtc_dial(
            dial_ip.as_ptr(),
            port,
            fingerprint.as_ptr(),
            fingerprint.len(),
            version,
        );
        assert!(!client.is_null(), "{}", last_error());
        let server = accept.join().unwrap() as *mut HsWebRtcConnection;
        assert!(!server.is_null(), "{}", last_error());

        exchange_noise_channel_data(client, server);
        hs_webrtc_connection_close(client);
        hs_webrtc_connection_close(server);
        hs_webrtc_listener_close(listener);
    }

    fn accept_connection(listener_address: usize) -> usize {
        loop {
            let mut status = 0;
            let connection =
                hs_webrtc_listener_accept(listener_address as *const HsWebRtcListener, &mut status);
            match status {
                0 => return connection as usize,
                1 => thread::sleep(Duration::from_millis(2)),
                _ => panic!("{}", last_error()),
            }
        }
    }

    fn exchange_noise_channel_data(
        client: *mut HsWebRtcConnection,
        server: *mut HsWebRtcConnection,
    ) {
        let client_channel = hs_webrtc_connection_noise_channel(client);
        let server_channel = hs_webrtc_connection_noise_channel(server);
        let payload = b"noise handshake";
        assert_eq!(
            hs_webrtc_channel_send(client_channel, payload.as_ptr(), payload.len()),
            0
        );
        let mut received = ptr::null_mut();
        let mut received_len = 0;
        assert_eq!(
            hs_webrtc_channel_recv(server_channel, &mut received, &mut received_len),
            0
        );
        assert_eq!(
            unsafe { slice::from_raw_parts(received, received_len) },
            payload
        );
        hs_webrtc_bytes_free(received, received_len);
        hs_webrtc_channel_close(client_channel);
        hs_webrtc_channel_close(server_channel);
    }

    fn last_error() -> String {
        unsafe { CStr::from_ptr(hs_webrtc_last_error()) }
            .to_string_lossy()
            .into_owned()
    }
}
