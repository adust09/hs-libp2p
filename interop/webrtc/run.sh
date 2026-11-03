#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose=(docker compose -f "$repo_root/docker-compose.webrtc-relay.yml")

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${compose[@]}" build js-interop hs-peer

WEBRTC_JS_ROLE=hs-listener WEBRTC_HS_DIALER=false \
  "${compose[@]}" up --abort-on-container-exit --exit-code-from js-interop
"${compose[@]}" down -v

WEBRTC_JS_ROLE=js-listener WEBRTC_HS_DIALER=true \
  "${compose[@]}" up --abort-on-container-exit --exit-code-from hs-peer
