pub struct ParsedUsername {
    pub server_ufrag: String,
    pub client_ufrag: String,
    pub client_password: String,
}

pub fn parse_username(packet: &[u8]) -> Option<ParsedUsername> {
    if packet.len() < 20 || packet[0..2] != [0x00, 0x01] || packet[4..8] != [0x21, 0x12, 0xa4, 0x42]
    {
        return None;
    }
    let message_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if message_len + 20 > packet.len() {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= message_len + 20 {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        offset += 4;
        if offset + len > packet.len() {
            return None;
        }
        if kind == 0x0006 {
            return parse_username_value(&packet[offset..offset + len]);
        }
        offset += (len + 3) & !3;
    }
    None
}

fn parse_username_value(value: &[u8]) -> Option<ParsedUsername> {
    let username = std::str::from_utf8(value).ok()?;
    let (server_ufrag, client_ufrag) = username.split_once(':')?;
    if !valid_ice_ufrag(server_ufrag) || !valid_ice_ufrag(client_ufrag) {
        return None;
    }
    let client_password = if let Some(value) = server_ufrag.strip_prefix(super::V2_PREFIX) {
        if !valid_ice_password(value) {
            return None;
        }
        value.to_owned()
    } else if server_ufrag.starts_with(super::V1_PREFIX) {
        server_ufrag.to_owned()
    } else {
        return None;
    };
    Some(ParsedUsername {
        server_ufrag: server_ufrag.to_owned(),
        client_ufrag: client_ufrag.to_owned(),
        client_password,
    })
}

fn valid_ice_chars(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

fn valid_ice_ufrag(value: &str) -> bool {
    (4..=256).contains(&value.len()) && valid_ice_chars(value)
}

fn valid_ice_password(value: &str) -> bool {
    (22..=256).contains(&value.len()) && valid_ice_chars(value)
}
