<p align="center">
  <a href="https://libp2p.io/">
    <img width="250" src="https://raw.githubusercontent.com/libp2p/libp2p/0a132b94943ef9eb187c16920dd0464da9524285/logo/black-bg-2.png" alt="libp2p logo">
  </a>
</p>

# hs-libp2p

A Haskell implementation of the [libp2p](https://libp2p.io/) modular peer-to-peer networking stack.

## Motivation

Implementation diversity is a core resilience property of decentralized networks:
a bug in one client must not be able to take down the whole network. Yet in the
Ethereum ecosystem — whose consensus layer is built on libp2p — there are
virtually no client implementations written in a pure functional language.
hs-libp2p exists to widen that diversity: a complete, spec-conformant libp2p
stack in Haskell, with the type-level guarantees and STM-based concurrency that
purely functional programming brings to protocol implementation.

## Upstream Collaboration

The project is part of the [libp2p/unified-testing](https://github.com/libp2p/unified-testing)
cross-implementation interop effort, joined at the invitation of a libp2p
maintainer. The codebase receives code review from libp2p maintainers, and
official integration into the unified testing suite is planned within 2027.
CI exercises hs ↔ go interoperability over TCP, WebSocket, native QUIC v1, WebTransport,
and WebRTC Direct, plus hs ↔ js standard WebRTC through Circuit Relay v2.
Local interop evidence lives in `interop/RESULTS.md`.

## Quickstart

The WebRTC lines below require building with `cabal build -fwebrtc`.

```haskell
import LibP2P
import LibP2P.Crypto.Key (publicKey)

main :: IO ()
main = do
  -- Generate identity
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)

  -- Create and configure switch
  sw <- newSwitch pid kp
  tcp <- newTCPTransport
  websocket <- newWebSocketTransport
  quic <- newQUICTransport kp
  webtransport <- newWebTransportTransport kp
  webrtc <- newWebRTCTransport kp
  addTransport sw tcp
  addTransport sw websocket
  addTransport sw quic
  addTransport sw webtransport
  addTransport sw webrtc
  registerIdentifyHandlers sw
  registerPingHandler sw

  -- Start listening
  addrs <- switchListen sw defaultConnectionGater
    [ Multiaddr [IP4 0x7f000001, TCP 0]
    , Multiaddr [IP4 0x7f000001, TCP 0, WS]
    , Multiaddr [IP4 0x7f000001, UDP 0, QuicV1]
    , Multiaddr [IP4 0x7f000001, UDP 0, QuicV1, WebTransport]
    , Multiaddr [IP4 0x7f000001, UDP 0, WebRTCDirect]
    ]
  putStrLn $ "Listening on: " ++ show addrs

  -- Dial a remote peer
  -- result <- dial sw remotePeerId [remoteAddr]

  -- Clean shutdown
  switchClose sw
```

`newWebTransportTransport` supports `/quic-v1/webtransport` dial/listen with
short-lived self-signed certificates, `/certhash` verification, and Noise-based
peer authentication.

`newWebRTCTransport` supports WebRTC Direct v2 with v1 fallback, DTLS
`/certhash` verification, Noise prologue binding, and SCTP data-channel streams.
`webRTCTransport sw defaultWebRTCConfig` adds standard relay-signaled WebRTC
for `/p2p-circuit/webrtc` addresses; register the Circuit Relay v2 handlers and
TCP transport on the same switch first.

`newWebSocketTransport` supports `/ws` dial/listen and verified `/wss` dialing.
To listen on `/wss`, load a Web-PKI `Credential`, set
`webSocketServerTLSParams = Just (webSocketServerParams credential)` on
`defaultWebSocketConfig`, and use `newWebSocketTransportWithConfig`.

## Building

Requires **GHC 9.10.x** (the `cacophony` dependency requires `base < 4.22`).
The optional WebRTC transports additionally require **Rust 1.85+** and
is enabled with `-fwebrtc`.

```bash
# Build
cabal build

# Build with WebRTC support
cabal build -fwebrtc

# Run tests
cabal test

# Build documentation
cabal haddock
```

## Tests

More than 1,400 tests cover all components, including unit tests, property
tests, and TCP/WebSocket/QUIC/WebTransport/WebRTC loopback tests. CI additionally
runs bidirectional go-libp2p transport interop and standard WebRTC interop with
js-libp2p.

```bash
# Run all tests
cabal test --test-show-details=streaming

# Run specific test module
cabal test --test-option="--match=Integration"
```

## Documentation

**[API Reference](https://adust09.github.io/hs-libp2p/)** — Generated Haddock documentation.

## Specification

Based on the [libp2p specification](https://github.com/libp2p/specs).
Reference implementations: [go-libp2p](https://github.com/libp2p/go-libp2p),
[rust-libp2p](https://github.com/libp2p/rust-libp2p).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch, review, and release
process. Issues labeled `good first issue` are a good place to start.

## License

MIT
