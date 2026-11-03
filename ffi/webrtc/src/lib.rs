use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, c_char};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::ptr;
use std::slice;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use str0m::channel::{ChannelConfig, ChannelId};
use str0m::config::DtlsCert;
use str0m::crypto::{CryptoProvider, Fingerprint};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};

mod direct;
mod signaling;
mod stun;

use direct::{ParsedUsername, parse_username};

const V1_PREFIX: &str = "libp2p+webrtc+v1/";
const V2_PREFIX: &str = "libp2p+webrtc+v2/";
const MAX_PACKET_SIZE: usize = 2048;
const MAX_CONNECTIONS: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("unknown WebRTC error").unwrap());
}

fn set_error(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(sanitized).unwrap();
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

struct ChannelState {
    messages: VecDeque<Vec<u8>>,
    open: bool,
    closed: bool,
    error: Option<String>,
}

struct SharedChannel {
    state: Mutex<ChannelState>,
    ready: Condvar,
}

impl SharedChannel {
    fn new() -> Self {
        Self {
            state: Mutex::new(ChannelState {
                messages: VecDeque::new(),
                open: false,
                closed: false,
                error: None,
            }),
            ready: Condvar::new(),
        }
    }

    fn push(&self, bytes: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.messages.push_back(bytes);
        self.ready.notify_all();
    }

    fn mark_open(&self) {
        let mut state = self.state.lock().unwrap();
        state.open = true;
        self.ready.notify_all();
    }

    fn mark_closed(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.ready.notify_all();
    }

    fn fail(&self, message: &str) {
        let mut state = self.state.lock().unwrap();
        state.error = Some(message.to_owned());
        self.ready.notify_all();
    }
}

struct ConnectionState {
    ready: bool,
    dtls_connected: bool,
    initial_channel_open: bool,
    closed: bool,
    error: Option<String>,
    local_fingerprint: Vec<u8>,
    remote_fingerprint: Vec<u8>,
    channels: HashMap<u64, Arc<SharedChannel>>,
    incoming: VecDeque<u64>,
}

struct SharedConnection {
    state: Mutex<ConnectionState>,
    ready: Condvar,
    command: mpsc::Sender<Command>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl SharedConnection {
    fn new(
        command: mpsc::Sender<Command>,
        local_fingerprint: Vec<u8>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Self {
        let noise = Arc::new(SharedChannel::new());
        Self {
            state: Mutex::new(ConnectionState {
                ready: false,
                dtls_connected: false,
                initial_channel_open: false,
                closed: false,
                error: None,
                local_fingerprint,
                remote_fingerprint: Vec::new(),
                channels: HashMap::from([(0, noise)]),
                incoming: VecDeque::new(),
            }),
            ready: Condvar::new(),
            command,
            local_addr,
            remote_addr,
        }
    }

    fn fail(&self, message: impl Into<String>) {
        let message = message.into();
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.error = Some(message.clone());
        for channel in state.channels.values() {
            channel.fail(&message);
        }
        self.ready.notify_all();
    }

    fn mark_dtls_connected(&self, remote_fingerprint: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.dtls_connected = true;
        state.remote_fingerprint = remote_fingerprint;
        state.ready = state.initial_channel_open;
        self.ready.notify_all();
    }

    fn mark_initial_channel_open(&self) {
        let mut state = self.state.lock().unwrap();
        state.initial_channel_open = true;
        state.ready = state.dtls_connected;
        self.ready.notify_all();
    }
}

enum Command {
    OpenChannel {
        response: mpsc::Sender<Result<u64, String>>,
    },
    Send {
        token: u64,
        data: Vec<u8>,
        response: mpsc::Sender<Result<(), String>>,
    },
    CloseChannel {
        token: u64,
    },
    AddRemoteCandidate {
        candidate: Candidate,
        response: mpsc::Sender<Result<(), String>>,
    },
    Close,
}

struct PendingSend {
    channel_id: ChannelId,
    data: Vec<u8>,
    response: mpsc::Sender<Result<(), String>>,
}

struct ConnectionRuntime {
    rtc: Rtc,
    shared: Arc<SharedConnection>,
    command_rx: mpsc::Receiver<Command>,
    channels: HashMap<u64, ChannelId>,
    reverse_channels: HashMap<ChannelId, u64>,
    pending_sends: VecDeque<PendingSend>,
    next_token: u64,
    next_timeout: Instant,
    accepted: bool,
    close_initial_on_open: bool,
}

impl ConnectionRuntime {
    fn new_direct(mut rtc: Rtc, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let initial = rtc.direct_api().create_data_channel(ChannelConfig {
            negotiated: Some(0),
            label: String::new(),
            ..Default::default()
        });
        Self::new(rtc, local_addr, remote_addr, Some(initial), false)
    }

    fn new_signaled(
        rtc: Rtc,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        initial: Option<ChannelId>,
    ) -> Self {
        Self::new(rtc, local_addr, remote_addr, initial, true)
    }

    fn new(
        mut rtc: Rtc,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        initial: Option<ChannelId>,
        close_initial_on_open: bool,
    ) -> Self {
        let local_fingerprint = rtc.direct_api().local_dtls_fingerprint().bytes.clone();
        let (command_tx, command_rx) = mpsc::channel();
        let shared = Arc::new(SharedConnection::new(
            command_tx,
            local_fingerprint,
            local_addr,
            remote_addr,
        ));
        let channels = initial
            .map(|id| HashMap::from([(0, id)]))
            .unwrap_or_default();
        let reverse_channels = initial
            .map(|id| HashMap::from([(id, 0)]))
            .unwrap_or_default();
        Self {
            rtc,
            shared,
            command_rx,
            channels,
            reverse_channels,
            pending_sends: VecDeque::new(),
            next_token: 1,
            next_timeout: Instant::now(),
            accepted: false,
            close_initial_on_open,
        }
    }

    fn process_commands(&mut self) -> bool {
        while let Ok(command) = self.command_rx.try_recv() {
            match command {
                Command::OpenChannel { response } => {
                    let id = self.rtc.direct_api().create_data_channel(ChannelConfig {
                        label: String::new(),
                        ..Default::default()
                    });
                    let token = self.next_token;
                    self.next_token += 1;
                    self.channels.insert(token, id);
                    self.reverse_channels.insert(id, token);
                    self.shared
                        .state
                        .lock()
                        .unwrap()
                        .channels
                        .insert(token, Arc::new(SharedChannel::new()));
                    let _ = response.send(Ok(token));
                }
                Command::Send {
                    token,
                    data,
                    response,
                } => {
                    if let Some(channel_id) = self.channels.get(&token).copied() {
                        self.pending_sends.push_back(PendingSend {
                            channel_id,
                            data,
                            response,
                        });
                    } else {
                        let _ = response.send(Err("unknown WebRTC data channel".into()));
                    }
                }
                Command::CloseChannel { token } => {
                    if let Some(channel_id) = self.channels.get(&token).copied() {
                        self.rtc.direct_api().close_data_channel(channel_id);
                    }
                }
                Command::AddRemoteCandidate {
                    candidate,
                    response,
                } => {
                    self.rtc.add_remote_candidate(candidate);
                    let _ = response.send(Ok(()));
                }
                Command::Close => {
                    self.shared.state.lock().unwrap().closed = true;
                    return false;
                }
            }
        }
        true
    }

    fn flush_sends(&mut self) {
        let mut remaining = VecDeque::new();
        while let Some(pending) = self.pending_sends.pop_front() {
            let result = match self.rtc.channel(pending.channel_id) {
                Some(mut channel) => channel.write(true, &pending.data),
                None => {
                    let _ = pending
                        .response
                        .send(Err("WebRTC data channel is closed".into()));
                    continue;
                }
            };
            match result {
                Ok(true) => {
                    let _ = pending.response.send(Ok(()));
                }
                Ok(false) => remaining.push_back(pending),
                Err(err) => {
                    let _ = pending.response.send(Err(err.to_string()));
                }
            }
        }
        self.pending_sends = remaining;
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::Connected => self.handle_connected(),
            Event::ChannelOpen(id, label) => self.handle_channel_open(id, &label),
            Event::ChannelData(data) => {
                if let Some(channel) = self.channel(data.id) {
                    channel.push(data.data);
                }
            }
            Event::ChannelClose(id) => {
                if let Some(channel) = self.channel(id) {
                    channel.mark_closed();
                }
            }
            Event::Closed => self.shared.fail("WebRTC connection closed"),
            _ => {}
        }
    }

    fn handle_connected(&mut self) {
        let remote = self
            .rtc
            .direct_api()
            .remote_dtls_fingerprint()
            .map(|fingerprint| fingerprint.bytes.clone())
            .unwrap_or_default();
        self.shared.mark_dtls_connected(remote);
    }

    fn handle_channel_open(&mut self, id: ChannelId, label: &str) {
        let is_initial = self.close_initial_on_open && label == "init";
        let token = self.channel_token(id, is_initial);
        if let Some(channel) = self.shared_channel(token) {
            channel.mark_open();
        }
        if token == 0 {
            self.shared.mark_initial_channel_open();
            if self.close_initial_on_open {
                self.rtc.direct_api().close_data_channel(id);
            }
        }
    }

    fn channel_token(&mut self, id: ChannelId, is_initial: bool) -> u64 {
        if let Some(token) = self.reverse_channels.get(&id).copied() {
            return token;
        }
        let token = if is_initial { 0 } else { self.next_token };
        if !is_initial {
            self.next_token += 1;
        }
        self.channels.insert(token, id);
        self.reverse_channels.insert(id, token);
        let mut state = self.shared.state.lock().unwrap();
        state.channels.insert(token, Arc::new(SharedChannel::new()));
        if !is_initial {
            state.incoming.push_back(token);
        }
        self.shared.ready.notify_all();
        token
    }

    fn channel(&self, id: ChannelId) -> Option<Arc<SharedChannel>> {
        self.reverse_channels
            .get(&id)
            .and_then(|token| self.shared_channel(*token))
    }

    fn shared_channel(&self, token: u64) -> Option<Arc<SharedChannel>> {
        self.shared
            .state
            .lock()
            .unwrap()
            .channels
            .get(&token)
            .cloned()
    }

    fn drain_output(&mut self, socket: &UdpSocket) -> Result<(), String> {
        loop {
            match self.rtc.poll_output().map_err(|err| err.to_string())? {
                Output::Transmit(transmit) => {
                    let bytes: Vec<u8> = transmit.contents.into();
                    socket
                        .send_to(&bytes, transmit.destination)
                        .map_err(|err| err.to_string())?;
                }
                Output::Event(event) => self.handle_event(event),
                Output::Timeout(timeout) => {
                    self.next_timeout = timeout;
                    break;
                }
            }
        }
        Ok(())
    }

    fn tick(&mut self, socket: &UdpSocket, now: Instant) -> Result<bool, String> {
        if !self.process_commands() {
            return Ok(false);
        }
        self.flush_sends();
        if now >= self.next_timeout {
            self.rtc
                .handle_input(Input::Timeout(now))
                .map_err(|err| err.to_string())?;
        }
        self.drain_output(socket)?;
        Ok(self.rtc.is_alive() && !self.shared.state.lock().unwrap().closed)
    }

    fn receive(&mut self, receive: Receive<'_>) -> Result<(), String> {
        self.rtc
            .handle_input(Input::Receive(Instant::now(), receive))
            .map_err(|err| err.to_string())
    }
}

pub struct HsWebRtcListener {
    shared: Arc<ListenerShared>,
    worker: Option<JoinHandle<()>>,
}

struct ListenerState {
    incoming: VecDeque<Arc<SharedConnection>>,
    closed: bool,
    error: Option<String>,
}

struct ListenerShared {
    state: Mutex<ListenerState>,
    ready: Condvar,
    shutdown: AtomicBool,
    fingerprint: Vec<u8>,
    local_addr: SocketAddr,
}

pub struct HsWebRtcConnection {
    shared: Arc<SharedConnection>,
}

pub struct HsWebRtcChannel {
    connection: Arc<SharedConnection>,
    token: u64,
}

fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(str0m_rust_crypto::default_provider())
}

fn generate_certificate(provider: &CryptoProvider) -> Result<DtlsCert, String> {
    provider
        .dtls_provider
        .generate_certificate()
        .ok_or_else(|| "str0m crypto provider cannot generate a certificate".to_owned())
}

fn rtc_config(provider: Arc<CryptoProvider>, certificate: DtlsCert) -> RtcConfig {
    RtcConfig::new()
        .set_crypto_provider(provider)
        .set_dtls_cert(certificate)
}

fn parse_ip(ip: *const c_char) -> Result<IpAddr, String> {
    if ip.is_null() {
        return Err("IP address is null".into());
    }
    let text = unsafe { CStr::from_ptr(ip) }
        .to_str()
        .map_err(|_| "IP address is not UTF-8")?;
    IpAddr::from_str(text).map_err(|err| err.to_string())
}

fn configure_dial(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    remote_fingerprint: Vec<u8>,
    version: u8,
) -> Result<ConnectionRuntime, String> {
    let provider = crypto_provider();
    let certificate = generate_certificate(&provider)?;
    let mut rtc = rtc_config(provider, certificate).build(Instant::now());
    rtc.add_local_candidate(Candidate::host(local_addr, "udp").map_err(|err| err.to_string())?);
    rtc.add_remote_candidate(Candidate::host(remote_addr, "udp").map_err(|err| err.to_string())?);
    let local = rtc.direct_api().local_ice_credentials();
    let server_credential = dial_server_credential(&mut rtc, local, version)?;
    rtc.direct_api()
        .set_remote_ice_credentials(server_credential);
    rtc.direct_api().set_remote_fingerprint(Fingerprint {
        hash_func: "sha-256".into(),
        bytes: remote_fingerprint,
    });
    rtc.direct_api().set_ice_controlling(true);
    rtc.direct_api()
        .start_dtls(true)
        .map_err(|err| err.to_string())?;
    rtc.direct_api().start_sctp(true);
    Ok(ConnectionRuntime::new_direct(rtc, local_addr, remote_addr))
}

fn dial_server_credential(rtc: &mut Rtc, local: IceCreds, version: u8) -> Result<IceCreds, String> {
    let (prefix, value) = match version {
        1 => (V1_PREFIX, local.ufrag),
        2 => (V2_PREFIX, local.pass),
        _ => return Err("unsupported WebRTC Direct version".into()),
    };
    let credential_value = format!("{prefix}{value}");
    let credentials = IceCreds {
        ufrag: credential_value.clone(),
        pass: credential_value,
    };
    if version == 1 {
        rtc.direct_api()
            .set_local_ice_credentials(credentials.clone());
    }
    Ok(credentials)
}

fn configure_server(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    parsed: ParsedUsername,
    provider: Arc<CryptoProvider>,
    certificate: DtlsCert,
) -> Result<ConnectionRuntime, String> {
    let mut rtc = rtc_config(provider, certificate)
        .set_ice_lite(true)
        .set_fingerprint_verification(false)
        .build(Instant::now());
    rtc.add_local_candidate(Candidate::host(local_addr, "udp").map_err(|err| err.to_string())?);
    rtc.add_remote_candidate(Candidate::host(remote_addr, "udp").map_err(|err| err.to_string())?);
    rtc.direct_api().set_local_ice_credentials(IceCreds {
        ufrag: parsed.server_ufrag.clone(),
        pass: parsed.server_ufrag,
    });
    rtc.direct_api().set_remote_ice_credentials(IceCreds {
        ufrag: parsed.client_ufrag,
        pass: parsed.client_password,
    });
    rtc.direct_api().set_remote_fingerprint(Fingerprint {
        hash_func: "sha-256".into(),
        bytes: vec![0; 32],
    });
    rtc.direct_api().set_ice_controlling(false);
    rtc.direct_api()
        .start_dtls(false)
        .map_err(|err| err.to_string())?;
    rtc.direct_api().start_sctp(false);
    Ok(ConnectionRuntime::new_direct(rtc, local_addr, remote_addr))
}

fn listener_loop(
    socket: UdpSocket,
    shared: Arc<ListenerShared>,
    provider: Arc<CryptoProvider>,
    certificate: DtlsCert,
) {
    let mut connections = Vec::new();
    let mut buffer = vec![0u8; MAX_PACKET_SIZE];
    while !shared.shutdown.load(Ordering::Relaxed) {
        if let Err(err) = receive_listener_packets(
            &socket,
            &shared,
            &provider,
            &certificate,
            &mut connections,
            &mut buffer,
        ) {
            fail_listener(&shared, err);
            return;
        }
        connections = tick_listener_connections(&socket, &shared, connections);
        thread::sleep(Duration::from_millis(2));
    }
    for connection in connections {
        connection.shared.fail("WebRTC listener closed");
    }
    fail_listener(&shared, "WebRTC listener closed".into());
}

fn receive_listener_packets(
    socket: &UdpSocket,
    shared: &ListenerShared,
    provider: &Arc<CryptoProvider>,
    certificate: &DtlsCert,
    connections: &mut Vec<ConnectionRuntime>,
    buffer: &mut [u8],
) -> Result<(), String> {
    loop {
        match socket.recv_from(buffer) {
            Ok((size, source)) => handle_listener_packet(
                &buffer[..size],
                source,
                shared.local_addr,
                provider,
                certificate,
                connections,
            ),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) => return Err(err.to_string()),
        }
    }
}

fn handle_listener_packet(
    packet: &[u8],
    source: SocketAddr,
    bound_addr: SocketAddr,
    provider: &Arc<CryptoProvider>,
    certificate: &DtlsCert,
    connections: &mut Vec<ConnectionRuntime>,
) {
    if let Some(connection) = connections
        .iter_mut()
        .find(|connection| connection.shared.remote_addr == source)
    {
        let local_addr = connection.shared.local_addr;
        let Ok(receive) = Receive::new(Protocol::Udp, source, local_addr, packet) else {
            return;
        };
        if let Err(err) = connection.receive(receive) {
            connection.shared.fail(err);
        }
        return;
    }
    if connections.len() >= MAX_CONNECTIONS {
        return;
    }
    let Some(parsed) = parse_username(packet) else {
        return;
    };
    let Ok(local_addr) = listener_addr_for_remote(bound_addr, source) else {
        return;
    };
    let Ok(receive) = Receive::new(Protocol::Udp, source, local_addr, packet) else {
        return;
    };
    if let Ok(mut connection) = configure_server(
        local_addr,
        source,
        parsed,
        provider.clone(),
        certificate.clone(),
    ) {
        if let Err(err) = connection.receive(receive) {
            connection.shared.fail(err);
        }
        connections.push(connection);
    }
}

fn listener_addr_for_remote(
    bound_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<SocketAddr, String> {
    if !bound_addr.ip().is_unspecified() {
        return Ok(bound_addr);
    }
    let probe_addr = match remote_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let probe = UdpSocket::bind(probe_addr).map_err(|err| err.to_string())?;
    probe.connect(remote_addr).map_err(|err| err.to_string())?;
    let routed_ip = probe.local_addr().map_err(|err| err.to_string())?.ip();
    Ok(SocketAddr::new(routed_ip, bound_addr.port()))
}

fn tick_listener_connections(
    socket: &UdpSocket,
    shared: &ListenerShared,
    connections: Vec<ConnectionRuntime>,
) -> Vec<ConnectionRuntime> {
    let now = Instant::now();
    connections
        .into_iter()
        .filter_map(|mut connection| match connection.tick(socket, now) {
            Ok(true) => {
                queue_accepted_connection(shared, &mut connection);
                Some(connection)
            }
            Ok(false) => {
                connection.shared.fail("WebRTC connection closed");
                None
            }
            Err(err) => {
                connection.shared.fail(err);
                None
            }
        })
        .collect()
}

fn queue_accepted_connection(shared: &ListenerShared, connection: &mut ConnectionRuntime) {
    let ready = connection.shared.state.lock().unwrap().ready;
    if !ready || connection.accepted {
        return;
    }
    connection.accepted = true;
    let mut state = shared.state.lock().unwrap();
    state.incoming.push_back(connection.shared.clone());
    shared.ready.notify_all();
}

fn fail_listener(shared: &ListenerShared, message: String) {
    let mut state = shared.state.lock().unwrap();
    state.error = Some(message);
    state.closed = true;
    shared.ready.notify_all();
}

mod ffi;
mod ffi_signaling;
