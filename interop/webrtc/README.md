# Standard WebRTC interoperability

This harness verifies standard relay-signaled WebRTC in both directions against
js-libp2p:

- js-libp2p dialer → hs-libp2p listener
- hs-libp2p dialer → js-libp2p listener

The js-libp2p container also runs the Circuit Relay v2 server used for SDP
signaling. Redis coordinates the relay and listener multiaddrs.

Run both directions from the repository root:

```bash
./interop/webrtc/run.sh
```

A successful run prints `js_to_hs_ping_ms` for the first direction and the
standard latency YAML for the reverse direction.
