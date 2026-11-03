use super::*;

pub struct HsWebRtcSignaling {
    setup: signaling::SignalingSetup,
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_offer_new(
    bind_ip: *const c_char,
    stun_servers: *const c_char,
) -> *mut HsWebRtcSignaling {
    signaling_new(bind_ip, stun_servers, None)
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_answer_new(
    bind_ip: *const c_char,
    stun_servers: *const c_char,
    offer: *const c_char,
) -> *mut HsWebRtcSignaling {
    signaling_new(bind_ip, stun_servers, Some(offer))
}

fn signaling_new(
    bind_ip: *const c_char,
    stun_servers: *const c_char,
    offer: Option<*const c_char>,
) -> *mut HsWebRtcSignaling {
    let result = (|| -> Result<HsWebRtcSignaling, String> {
        let ip = parse_ip(bind_ip)?;
        let servers = required_string(stun_servers, "STUN servers")?;
        let setup = match offer {
            Some(value) => signaling::SignalingSetup::answer(
                ip,
                &servers,
                &required_string(value, "SDP offer")?,
            )?,
            None => signaling::SignalingSetup::offer(ip, &servers)?,
        };
        Ok(HsWebRtcSignaling { setup })
    })();
    match result {
        Ok(setup) => Box::into_raw(Box::new(setup)),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_sdp(signaling: *const HsWebRtcSignaling) -> *mut c_char {
    if signaling.is_null() {
        set_error("signaling setup is null");
        return ptr::null_mut();
    }
    owned_c_string(unsafe { (*signaling).setup.sdp() })
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_candidate_count(
    signaling: *const HsWebRtcSignaling,
) -> usize {
    if signaling.is_null() {
        return 0;
    }
    unsafe { (*signaling).setup.candidates().len() }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_candidate(
    signaling: *const HsWebRtcSignaling,
    index: usize,
) -> *mut c_char {
    if signaling.is_null() {
        set_error("signaling setup is null");
        return ptr::null_mut();
    }
    match unsafe { (*signaling).setup.candidates().get(index) } {
        Some(candidate) => owned_c_string(candidate),
        None => {
            set_error("signaling candidate index is out of range");
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_add_candidate(
    signaling: *mut HsWebRtcSignaling,
    candidate: *const c_char,
) -> i32 {
    if signaling.is_null() {
        set_error("signaling setup is null");
        return -1;
    }
    let result = required_string(candidate, "ICE candidate")
        .and_then(|value| unsafe { (*signaling).setup.add_remote_candidate(&value) });
    status_result(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_accept_answer(
    signaling: *mut HsWebRtcSignaling,
    answer: *const c_char,
) -> i32 {
    if signaling.is_null() {
        set_error("signaling setup is null");
        return -1;
    }
    let result = required_string(answer, "SDP answer")
        .and_then(|value| unsafe { (*signaling).setup.accept_answer(&value) });
    status_result(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_start(
    signaling: *mut HsWebRtcSignaling,
) -> *mut HsWebRtcConnection {
    if signaling.is_null() {
        set_error("signaling setup is null");
        return ptr::null_mut();
    }
    let signaling = unsafe { Box::from_raw(signaling) };
    match signaling.setup.start() {
        Ok(shared) => Box::into_raw(Box::new(HsWebRtcConnection { shared })),
        Err(err) => {
            set_error(err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_signaling_close(signaling: *mut HsWebRtcSignaling) {
    if !signaling.is_null() {
        unsafe { drop(Box::from_raw(signaling)) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_string_free(value: *mut c_char) {
    if !value.is_null() {
        unsafe { drop(CString::from_raw(value)) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_add_candidate(
    connection: *const HsWebRtcConnection,
    candidate: *const c_char,
) -> i32 {
    if connection.is_null() {
        set_error("connection is null");
        return -1;
    }
    let result = required_string(candidate, "ICE candidate").and_then(|value| {
        let parsed = serde_json::from_str(&value).map_err(|err| err.to_string())?;
        add_remote_candidate(unsafe { &(*connection).shared }, parsed)
    });
    status_result(result)
}

fn add_remote_candidate(shared: &SharedConnection, candidate: Candidate) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    shared
        .command
        .send(Command::AddRemoteCandidate {
            candidate,
            response: tx,
        })
        .map_err(|_| "WebRTC connection worker stopped")?;
    rx.recv().map_err(|_| "WebRTC connection worker stopped")?
}

#[unsafe(no_mangle)]
pub extern "C" fn hs_webrtc_connection_wait_ready(connection: *const HsWebRtcConnection) -> i32 {
    if connection.is_null() {
        set_error("connection is null");
        return -1;
    }
    status_result(crate::ffi::await_connection(
        unsafe { &(*connection).shared },
        "WebRTC signaling connection",
    ))
}

fn required_string(value: *const c_char, label: &str) -> Result<String, String> {
    if value.is_null() {
        return Err(format!("{label} is null"));
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| format!("{label} is not UTF-8"))
}

fn owned_c_string(value: &str) -> *mut c_char {
    match CString::new(value) {
        Ok(string) => string.into_raw(),
        Err(_) => {
            set_error("WebRTC text contains a null byte");
            ptr::null_mut()
        }
    }
}

fn status_result(result: Result<(), String>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => {
            set_error(err);
            -1
        }
    }
}
