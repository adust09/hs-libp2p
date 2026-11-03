use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_TIMEOUT: Duration = Duration::from_millis(750);

static TRANSACTION_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn resolve_servers(input: &str) -> Vec<SocketAddr> {
    input
        .lines()
        .filter_map(|line| line.to_socket_addrs().ok())
        .flatten()
        .collect()
}

pub fn discover_mapping(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr, String> {
    let transaction = transaction_id();
    let request = binding_request(transaction);
    socket
        .set_read_timeout(Some(STUN_TIMEOUT))
        .map_err(|err| err.to_string())?;
    socket
        .send_to(&request, server)
        .map_err(|err| err.to_string())?;
    let mut buffer = [0u8; 1024];
    loop {
        let (size, source) = socket
            .recv_from(&mut buffer)
            .map_err(|err| err.to_string())?;
        if source == server {
            if let Some(address) = parse_binding_response(&buffer[..size], transaction) {
                return Ok(address);
            }
        }
    }
}

fn transaction_id() -> [u8; 12] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = TRANSACTION_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let mixed = nanos ^ (counter << 32) ^ u128::from(std::process::id());
    let bytes = mixed.to_be_bytes();
    let mut transaction = [0u8; 12];
    transaction.copy_from_slice(&bytes[4..]);
    transaction
}

fn binding_request(transaction: [u8; 12]) -> [u8; 20] {
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction);
    request
}

fn parse_binding_response(packet: &[u8], transaction: [u8; 12]) -> Option<SocketAddr> {
    if packet.len() < 20 || u16::from_be_bytes([packet[0], packet[1]]) != BINDING_SUCCESS {
        return None;
    }
    if packet[4..8] != MAGIC_COOKIE.to_be_bytes() || packet[8..20] != transaction {
        return None;
    }
    let body_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < 20 + body_length {
        return None;
    }
    parse_attributes(&packet[..20 + body_length], transaction)
}

fn parse_attributes(packet: &[u8], transaction: [u8; 12]) -> Option<SocketAddr> {
    let mut offset = 20;
    let mut mapped = None;
    while offset + 4 <= packet.len() {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let length = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        offset += 4;
        if offset + length > packet.len() {
            return None;
        }
        let value = &packet[offset..offset + length];
        if kind == XOR_MAPPED_ADDRESS {
            return parse_address(value, true, transaction);
        }
        if kind == MAPPED_ADDRESS {
            mapped = parse_address(value, false, transaction);
        }
        offset += (length + 3) & !3;
    }
    mapped
}

fn parse_address(value: &[u8], xor: bool, transaction: [u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 || value[0] != 0 {
        return None;
    }
    let mask = (MAGIC_COOKIE >> 16) as u16;
    let encoded_port = u16::from_be_bytes([value[2], value[3]]);
    let port = if xor {
        encoded_port ^ mask
    } else {
        encoded_port
    };
    match value[1] {
        0x01 if value.len() >= 8 => {
            let encoded = u32::from_be_bytes(value[4..8].try_into().ok()?);
            let address = if xor { encoded ^ MAGIC_COOKIE } else { encoded };
            Some(SocketAddr::new(IpAddr::V4(address.into()), port))
        }
        0x02 if value.len() >= 20 => {
            let mut bytes: [u8; 16] = value[4..20].try_into().ok()?;
            if xor {
                let mut mask_bytes = [0u8; 16];
                mask_bytes[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask_bytes[4..].copy_from_slice(&transaction);
                for (byte, mask_byte) in bytes.iter_mut().zip(mask_bytes) {
                    *byte ^= mask_byte;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(bytes.into()), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn discovers_xor_mapped_address_from_local_server() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let worker = thread::spawn(move || respond_once(server));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mapped = discover_mapping(&client, server_addr).unwrap();
        assert_eq!(mapped, client.local_addr().unwrap());
        worker.join().unwrap();
    }

    fn respond_once(socket: UdpSocket) {
        let mut request = [0u8; 256];
        let (size, source) = socket.recv_from(&mut request).unwrap();
        let transaction: [u8; 12] = request[8..20].try_into().unwrap();
        let response = xor_response(source, transaction);
        socket.send_to(&response, source).unwrap();
        assert!(size >= 20);
    }

    fn xor_response(address: SocketAddr, transaction: [u8; 12]) -> Vec<u8> {
        let SocketAddr::V4(address) = address else {
            panic!("test requires IPv4");
        };
        let mut response = vec![0u8; 32];
        response[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction);
        response[20..22].copy_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        response[25] = 0x01;
        response[26..28]
            .copy_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let encoded = u32::from(*address.ip()) ^ MAGIC_COOKIE;
        response[28..32].copy_from_slice(&encoded.to_be_bytes());
        response
    }
}
