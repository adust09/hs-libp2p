# Multi-stage build for the hs-libp2p perf test daemon.
# Used by the libp2p/unified-testing perf framework; build context is
# the repository root (perf/images.yaml: dockerfile: interop/perf/Dockerfile).

# Stage 1: Build with GHC 9.10
FROM haskell:9.10-slim-bookworm AS builder

WORKDIR /app

# Copy only the package description first, so the dependency-build layer below
# is cached and reused as long as hs-libp2p.cabal / cabal.project are unchanged.
COPY hs-libp2p.cabal cabal.project Setup.hs ./

# Fix ppad-sha256 ARM SHA2 intrinsic compilation on Docker (GCC 12).
# Only apply ARM-specific flags on aarch64; skip on x86_64.
# Must run before any build so the override is in effect.
RUN if [ "$(uname -m)" = "aarch64" ]; then \
      echo 'package ppad-sha256' >> cabal.project && \
      echo '  ghc-options: -optc-march=armv8-a+crypto' >> cabal.project; \
    fi

# Pre-build the library's dependencies. This is the expensive layer (crypton,
# cacophony, tls, lens, ...) and is cached unless the cabal file changes, so
# source-only edits skip it. We target the library (not the executable) because
# the executable depends on the local hs-libp2p library, which cannot be built
# before its source is copied below.
RUN cabal update && cabal build --only-dependencies lib:hs-libp2p

# Copy sources and build the project itself.
COPY src/ src/
COPY interop/ interop/
RUN cabal build libp2p-perf \
    && cp "$(cabal list-bin libp2p-perf)" /app/libp2p-perf \
    && strip /app/libp2p-perf

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libgmp10 \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/libp2p-perf /usr/local/bin/libp2p-perf

ENTRYPOINT ["libp2p-perf"]
