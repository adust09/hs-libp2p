use super::*;
use if_addrs::get_if_addrs;
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};

pub struct SignalingSetup {
    rtc: Rtc,
    socket: UdpSocket,
    local_addr: SocketAddr,
    sdp: String,
    candidates: Vec<String>,
    pending_offer: Option<SdpPendingOffer>,
    initial_channel: Option<ChannelId>,
}

impl SignalingSetup {
    pub fn offer(bind_ip: IpAddr, stun_servers: &str) -> Result<Self, String> {
        let (mut rtc, socket, local_addr, candidates) = configured_rtc(bind_ip, stun_servers)?;
        let mut changes = rtc.sdp_api();
        let initial_channel = changes.add_channel("init".to_owned());
        let (offer, pending_offer) = changes
            .apply()
            .ok_or_else(|| "WebRTC offer did not contain a negotiation change".to_owned())?;
        Ok(Self {
            rtc,
            socket,
            local_addr,
            sdp: strip_candidates(&offer.to_sdp_string()),
            candidates,
            pending_offer: Some(pending_offer),
            initial_channel: Some(initial_channel),
        })
    }

    pub fn answer(bind_ip: IpAddr, stun_servers: &str, offer: &str) -> Result<Self, String> {
        let (mut rtc, socket, local_addr, candidates) = configured_rtc(bind_ip, stun_servers)?;
        let parsed = SdpOffer::from_sdp_string(offer).map_err(|err| err.to_string())?;
        let answer = rtc
            .sdp_api()
            .accept_offer(parsed)
            .map_err(|err| err.to_string())?;
        Ok(Self {
            rtc,
            socket,
            local_addr,
            sdp: strip_candidates(&answer.to_sdp_string()),
            candidates,
            pending_offer: None,
            initial_channel: None,
        })
    }

    pub fn sdp(&self) -> &str {
        &self.sdp
    }

    pub fn candidates(&self) -> &[String] {
        &self.candidates
    }

    pub fn add_remote_candidate(&mut self, json: &str) -> Result<(), String> {
        let candidate: Candidate = serde_json::from_str(json).map_err(|err| err.to_string())?;
        self.rtc.add_remote_candidate(candidate);
        Ok(())
    }

    pub fn accept_answer(&mut self, answer: &str) -> Result<(), String> {
        let pending = self
            .pending_offer
            .take()
            .ok_or_else(|| "WebRTC offer has already accepted an answer".to_owned())?;
        let parsed = SdpAnswer::from_sdp_string(answer).map_err(|err| err.to_string())?;
        self.rtc
            .sdp_api()
            .accept_answer(pending, parsed)
            .map_err(|err| err.to_string())
    }

    pub fn start(self) -> Result<Arc<SharedConnection>, String> {
        if self.pending_offer.is_some() {
            return Err("WebRTC offer cannot start before accepting an answer".into());
        }
        self.socket
            .set_nonblocking(true)
            .map_err(|err| err.to_string())?;
        let remote_addr = unspecified_remote(self.local_addr);
        let runtime = ConnectionRuntime::new_signaled(
            self.rtc,
            self.local_addr,
            remote_addr,
            self.initial_channel,
        );
        let shared = runtime.shared.clone();
        thread::spawn(move || signaled_loop(self.socket, self.local_addr, runtime));
        Ok(shared)
    }
}

fn configured_rtc(
    requested_ip: IpAddr,
    stun_servers: &str,
) -> Result<(Rtc, UdpSocket, SocketAddr, Vec<String>), String> {
    let bind_ip = select_bind_ip(requested_ip)?;
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).map_err(|err| err.to_string())?;
    let local_addr = socket.local_addr().map_err(|err| err.to_string())?;
    let mut candidates = vec![Candidate::host(local_addr, "udp").map_err(|err| err.to_string())?];
    candidates.extend(gather_server_reflexive(&socket, local_addr, stun_servers));
    socket
        .set_read_timeout(None)
        .map_err(|err| err.to_string())?;
    let provider = crypto_provider();
    let certificate = generate_certificate(&provider)?;
    let mut rtc = rtc_config(provider, certificate).build(Instant::now());
    let accepted = candidates
        .into_iter()
        .filter_map(|candidate| rtc.add_local_candidate(candidate).cloned())
        .map(|candidate| serde_json::to_string(&candidate).map_err(|err| err.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((rtc, socket, local_addr, accepted))
}

fn select_bind_ip(requested: IpAddr) -> Result<IpAddr, String> {
    if !requested.is_unspecified() {
        return Ok(requested);
    }
    let want_v4 = requested.is_ipv4();
    let interfaces = get_if_addrs().map_err(|err| err.to_string())?;
    let matching = interfaces
        .iter()
        .map(|interface| interface.ip())
        .filter(|ip| ip.is_ipv4() == want_v4)
        .collect::<Vec<_>>();
    matching
        .iter()
        .copied()
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .or_else(|| matching.into_iter().find(|ip| ip.is_loopback()))
        .ok_or_else(|| "no local IP address is available for WebRTC".to_owned())
}

fn gather_server_reflexive(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    configured: &str,
) -> Vec<Candidate> {
    stun::resolve_servers(configured)
        .into_iter()
        .filter(|server| server.is_ipv4() == local_addr.is_ipv4())
        .filter_map(|server| stun::discover_mapping(socket, server).ok())
        .filter_map(|mapped| Candidate::server_reflexive(mapped, local_addr, "udp").ok())
        .collect()
}

fn strip_candidates(sdp: &str) -> String {
    sdp.split_inclusive('\n')
        .filter(|line| {
            let trimmed = line.trim_end_matches(['\r', '\n']);
            !trimmed.starts_with("a=candidate:") && trimmed != "a=end-of-candidates"
        })
        .collect()
}

fn unspecified_remote(local: SocketAddr) -> SocketAddr {
    match local {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    }
}

fn signaled_loop(socket: UdpSocket, local_addr: SocketAddr, mut runtime: ConnectionRuntime) {
    let mut buffer = vec![0u8; MAX_PACKET_SIZE];
    loop {
        if let Err(err) = receive_packets(&socket, local_addr, &mut runtime, &mut buffer) {
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

fn receive_packets(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_candidates_from_trickle_sdp() {
        let input =
            "v=0\r\na=candidate:1 1 udp 1 127.0.0.1 1 typ host\r\na=end-of-candidates\r\ns=-\r\n";
        assert_eq!(strip_candidates(input), "v=0\r\ns=-\r\n");
    }
}
