---
title: Transport-Interop Results
last_updated: 2026-10-24
tags:
  - interop
  - transport
  - testing
  - go-libp2p
  - js-libp2p
---

# Transport-Interop Results

This document records reproducible evidence that the `libp2p-interop` binary
(`interop/transport/Main.hs`) passes the upstream
[libp2p/test-plans](https://github.com/libp2p/test-plans/tree/master/transport-interop)
**ping** contract against go-libp2p, in both dialer and listener roles, over
**TCP + Noise/TLS + Yamux**, **WebSocket + Noise + Yamux**, native
**QUIC v1**, **WebTransport over HTTP/3**, and standard relay-signaled
**WebRTC**.

## Standard WebRTC interoperability (2026-10-24)

The `/p2p-circuit/webrtc` transport passed a Ping exchange in both directions
against `js-libp2p 3.5.1` and `@libp2p/webrtc 7.0.2`. A js-libp2p Circuit Relay
v2 server carried SDP offer/answer signaling; the resulting SCTP data channel
carried libp2p streams directly between the peers.

```bash
./interop/webrtc/run.sh
```

Both dialers exited 0. The js-libp2p client measured a 3 ms Ping RTT to the
Haskell listener. The Haskell client measured a 144.525 ms setup-plus-ping time
and a 4.171 ms Ping RTT to the js-libp2p listener. CI runs both directions.

## WebTransport interoperability (2026-10-23)

The `/quic-v1/webtransport` transport passed the ping contract in both
directions against `go-libp2p v0.48.0`, including `/certhash` certificate
verification, HTTP/3 Extended CONNECT, and Noise peer authentication.

```bash
# go-libp2p listener, hs-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.webtransport-cross.yml up --build \
  --exit-code-from hs-dialer redis go-listener hs-dialer

# hs-libp2p listener, go-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.webtransport-cross.yml up --build \
  --exit-code-from go-dialer redis hs-listener go-dialer
```

Both dialer containers exited 0. The Haskell client measured a 12.778 ms
handshake-plus-ping and 0.326 ms ping RTT; the Go client measured 12.840 ms and
0.152 ms respectively. CI runs both directions.

## WebSocket interoperability (2026-10-23)

The `/ws` transport passed the ping contract in both directions against
`go-libp2p v0.48.0`, with Noise and Yamux running over the WebSocket byte
stream.

```bash
# go-libp2p listener, hs-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.websocket-cross.yml up --build \
  --exit-code-from hs-dialer redis go-listener hs-dialer

# hs-libp2p listener, go-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.websocket-cross.yml up --build \
  --exit-code-from go-dialer redis hs-listener go-dialer
```

Both dialer containers exited 0. The Haskell client measured a 5.929 ms
handshake-plus-ping and 0.642 ms ping RTT; the Go client measured 6.872 ms and
0.192 ms respectively. CI runs both directions. `/wss` is covered separately
by loopback byte-stream and full Noise/Yamux/Ping integration tests with
explicit outer TLS server parameters.

## TLS 1.3 interoperability (2026-10-14)

The TCP transport passed the ping contract in both directions against
`go-libp2p v0.48.0` using the `/tls/1.0.0` secure channel and Yamux negotiated
inline through ALPN.

```bash
# go-libp2p listener, hs-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.tls-cross.yml up --build \
  --exit-code-from hs-dialer redis go-listener hs-dialer

# hs-libp2p listener, go-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.tls-cross.yml up --build \
  --exit-code-from go-dialer redis hs-listener go-dialer
```

Both dialer containers completed one libp2p Ping and exited 0. The Haskell
client measured an 11.043 ms handshake-plus-ping and 0.670 ms ping RTT; the Go
client measured 8.333 ms and 0.212 ms respectively. CI runs both directions.

Ping carries only 32 bytes, so it does not split a TLS record across TCP reads.
CI also runs a 10 MiB upload and download between two hs-libp2p peers over
TCP + TLS + Yamux:

```bash
docker compose -f docker-compose.perf.yml \
  -f docker-compose.perf-tls.yml up --build \
  --exit-code-from hs-perf-dialer redis hs-perf-listener hs-perf-dialer
```

## QUIC v1 interoperability (2026-09-14)

The QUIC transport passed the same ping contract in both directions against
`go-libp2p v0.48.0`. QUIC performs TLS 1.3 peer authentication and stream
multiplexing natively, so `SECURE_CHANNEL` and `MUXER` are unset.

```bash
# go-libp2p listener, hs-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.quic-cross.yml up --build \
  --exit-code-from hs-dialer redis go-listener hs-dialer

# hs-libp2p listener, go-libp2p dialer
docker compose -f docker-compose.cross.yml \
  -f docker-compose.quic-cross.yml up --build \
  --exit-code-from go-dialer redis hs-listener go-dialer
```

Both dialer containers completed one libp2p Ping and exited 0. The QUIC source
dependency is pinned in `cabal.project`; that revision includes client
certificate requests, RFC 9221 QUIC datagrams, and correct `RESET_STREAM`
final-size handling needed for go-libp2p interoperability. CI runs these two
commands after the TCP matrix.

## Historical TCP results

> **Update (2026-08-06, issue #129):** `interop/Main.hs` has since been migrated
> to the [libp2p/unified-testing](https://github.com/libp2p/unified-testing)
> "modern" transport contract (uppercase env vars, `TEST_KEY`-namespaced Redis
> keys, YAML results on stdout). The legacy-contract details below are kept as
> a historical record of the original test-plans runs; the go-libp2p cross
> tests now go through the key-translation shims in `docker-compose.cross.yml`.

### Environment

| Item | Value |
|------|-------|
| hs-libp2p commit | `d0b74b7` (plus the conformance fixes in this PR) |
| go-libp2p | `v0.48.0` (`062200be7aa1d18a0f54eefb17b0dbe2e96f0a79`) |
| Transport / Security / Muxer | `tcp` / `noise` / `yamux` |
| GHC (in Docker) | 9.10 (`haskell:9.10-slim-bookworm`) |
| Docker | 29.3.0, Compose v5.1.0 |
| Date | 2026-05-27 |

### Conformance fixes applied (verified against the upstream README)

- **Listener timeout exit code.** Per the README ("Listener", step 5), a listener that
  reaches `test_timeout_seconds` must exit with a non-zero code. `runListener` previously
  slept, closed the switch, and fell through to exit 0; it now logs and calls `exitFailure`.
- **Dialer metric semantics.** Per the README ("Dialer", steps 4–9) the dialer records
  `handshakeStartInstant`, connects, performs **one** ping (its round trip is `pingRTT`),
  and reports the total elapsed since the start as `handshakePlusOneRTT`. `runDialer`
  previously sent a *second* ping to measure `pingRTT`; it now uses the single ping for
  both metrics. The upstream-mandated key spelling `pingRTTMilllis` (triple L) is preserved.

### Results

Both directions exit 0 on the process whose exit code the framework keys on (the dialer),
asserted explicitly via `docker compose up --exit-code-from <dialer-service>`.

#### Direction 1 — go-libp2p listener, hs-libp2p dialer

Command:

```bash
docker compose -f docker-compose.cross.yml up --build \
  --exit-code-from hs-dialer redis go-listener hs-dialer
```

- go-listener bound `/ip4/172.19.0.3/tcp/40097`.
- hs-dialer dialed and printed to stdout:

  ```json
  {"handshakePlusOneRTTMillis":183.559457,"pingRTTMilllis":43.797114}
  ```

- **hs-dialer exited 0.** (go-listener exited 2 because `--exit-code-from` aborts the
  remaining services once the dialer finishes — expected, not a failure.)

#### Direction 2 — hs-libp2p listener, go-libp2p dialer

Command:

```bash
docker compose -f docker-compose.cross.yml up --build \
  --exit-code-from go-dialer redis hs-listener go-dialer
```

- hs-listener bound `/ip4/172.19.0.3/tcp/43701` and published it to Redis.
- go-dialer dialed and printed to stdout:

  ```json
  {"handshakePlusOneRTTMillis":179.622,"pingRTTMilllis":43.953}
  ```

- **go-dialer exited 0.** (hs-listener exited 137 = SIGKILL by the runner after the dialer
  finished — the normal flow described by the README.)

#### Listener timeout behavior

Running the listener with a short timeout and no dialer confirms the conformance fix:

```bash
docker compose -f docker-compose.cross.yml run --rm \
  -e test_timeout_seconds=5 hs-listener
# -> logs "Listener timed out waiting to be dialed", exit code 1
```

### Reproducing

1. Clone go-libp2p at the pinned commit into `./go-libp2p`:

   ```bash
   git clone --depth 1 --branch v0.48.0 https://github.com/libp2p/go-libp2p.git go-libp2p
   ```

2. Run the two cross-test directions with the commands above, or via the Makefile targets
   `make -C interop cross-test-go-listener` and `make -C interop cross-test-hs-listener`
   (note: the Makefile uses `--abort-on-container-exit`; prefer `--exit-code-from` to
   assert the dialer's exit code explicitly, as shown above).

### Scope notes

- This validates the upstream transport-interop **ping** contract against go-libp2p.
  Continuous proof in CI and upstream registration in `libp2p/test-plans` are tracked
  separately.
- A GossipSub cross-test against the bundled `interop/rust-peer/`
  (`make -C interop cross-gossipsub`) exists but validates GossipSub messaging, not the
  transport-interop ping spec; a true rust transport-interop ping check uses the official
  rust container and is deferred to the upstream-submission work.
