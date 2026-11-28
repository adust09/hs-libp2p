# Interop container images

Manifest of every container image this repository builds for
interoperability testing. Layout follows the
[libp2p/test-plans](https://github.com/libp2p/test-plans) convention: one
plain `Dockerfile` per implementation directory, with a suffixed filename
only when one directory holds several roles. The `interop/transport/`
directory also hosts the shared transport daemon sources, so its
WebRTC-enabled build keeps the suffixed `WebRTCDockerfile` name.

Base images are pinned as `tag@sha256:<digest>` in every `FROM` line. The
hole-punch peer additionally pins an apt snapshot, because Debian sid
repositories move independently of the image digest.

| Image | Dockerfile | Built by | Base images (all pinned) |
|---|---|---|---|
| hs-libp2p-interop | `Dockerfile` | transport-interop and gossipsub-interop CI jobs; `docker-compose.yml`, `docker-compose.cross.yml`, `docker-compose.gossipsub.yml` | `haskell:9.10-slim-bookworm`, `debian:bookworm-slim` |
| hs-libp2p-webrtc-interop | `interop/transport/WebRTCDockerfile` | transport-interop job (WebRTC Direct); `docker-compose.webrtc-cross.yml`, `docker-compose.webrtc-relay.yml` | `haskell:9.10-slim-bookworm`, `debian:bookworm-slim` |
| js-interop (js WebRTC peer) | `interop/impl/js/Dockerfile` | transport-interop job (standard WebRTC); `docker-compose.webrtc-relay.yml`, `interop/impl/js/run.sh` | `node:22-bookworm-slim` |
| hs-libp2p-perf | `interop/perf/Dockerfile` | perf-interop CI job; `docker-compose.perf.yml`, `docker-compose.perf-tls.yml`, `docker-compose.perf-cross.yml` | `haskell:9.10-slim-bookworm`, `debian:bookworm-slim` |
| nim-libp2p-perf | `interop/impl/nim/Dockerfile` | perf-interop job (nim cross direction); `docker-compose.perf-cross.yml` (context: `nim-libp2p` clone) | `nimlang/nim:2.2.12`, `debian:trixie-slim` |
| hs-libp2p-kad-dht-node | `interop/kad-dht-node/Dockerfile` | kad-dht-interop CI job; `docker-compose.kad-dht.yml`, `docker-compose.kad-dht-go.yml` | `haskell:9.10-slim-bookworm`, `debian:bookworm-slim` |
| hs-libp2p-kadserv-go | `interop/impl/go/Dockerfile` | kad-dht-interop job (GET_VALUE round-trip responder); `docker-compose.kad-dht-go.yml` | `golang:1.26-bookworm`, `gcr.io/distroless/static-debian12:nonroot` |
| hs-libp2p-gossipsub-rust | `interop/impl/rust/Dockerfile` | gossipsub-interop CI job; `docker-compose.gossipsub.yml` | `rust:1.85.1-slim-bookworm`, `debian:bookworm-slim` |
| hs-libp2p-hole-punch | `interop/hole-punch/Dockerfile` | hole-punch-self-test CI job; `docker-compose.hole-punch.yml` | `debian:sid-slim` + apt snapshot |
| hs-libp2p-hole-punch-router | `interop/hole-punch/router/Dockerfile` | hole-punch-self-test CI job; `docker-compose.hole-punch.yml` | `alpine:3.19` |

## Externally pinned paths

Four Dockerfiles must keep their path because upstream frameworks build
them by name (`source.dockerfile` entries in the framework `images.yaml`):

| Dockerfile | External referent |
|---|---|
| `Dockerfile` | [libp2p/unified-testing](https://github.com/libp2p/unified-testing) `transport/images.yaml`, `haskell-v0.1` (`dockerfile: Dockerfile`) |
| `interop/perf/Dockerfile` | libp2p/unified-testing `perf/images.yaml`, `haskell-v0.1` |
| `interop/kad-dht-node/Dockerfile` | libp2p/unified-testing `kad-dht/images.yaml`, `haskell` |
| `interop/hole-punch/Dockerfile` | libp2p/unified-testing and [adust09/unified-testing](https://github.com/adust09/unified-testing) `hole-punch/images.yaml`, `haskell-v0.1` |

Renaming any of these (or repositioning the suffixed
`interop/transport/WebRTCDockerfile`) requires updating the referencing
`images.yaml` in the unified-testing repositories in the same change.
