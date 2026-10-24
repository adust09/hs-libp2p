# Multi-stage build for hs-libp2p kad-dht interop node.
# Used by the libp2p/unified-testing kad-dht framework.
# Follows the same pattern as the transport interop Dockerfile at /Dockerfile.

# Stage 1: Build with GHC 9.10
FROM haskell:9.10-slim-bookworm AS builder

WORKDIR /app

# Copy package description first for dependency cache
COPY hs-libp2p.cabal cabal.project Setup.hs ./

# Fix ppad-sha256 ARM SHA2 intrinsic compilation on Docker (GCC 12).
# Only apply ARM-specific flags on aarch64; skip on x86_64.
# Must run before any build so the override is in effect.
RUN if [ "$(uname -m)" = "aarch64" ]; then \
      echo 'package ppad-sha256' >> cabal.project && \
      echo '  ghc-options: -optc-march=armv8-a+crypto' >> cabal.project; \
    fi

# Pre-build the library's dependencies
RUN cabal update && cabal build --only-dependencies lib:hs-libp2p

# Copy sources and build the kad-dht-node executable
COPY src/ src/
COPY interop/ interop/
RUN cabal build libp2p-kad-dht-node \
    && cp "$(cabal list-bin libp2p-kad-dht-node)" /app/libp2p-kad-dht-node \
    && strip /app/libp2p-kad-dht-node

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libgmp10 \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/libp2p-kad-dht-node /usr/local/bin/libp2p-kad-dht-node

ENTRYPOINT ["libp2p-kad-dht-node"]
