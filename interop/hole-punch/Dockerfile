# Multi-stage build for the hs-libp2p hole-punch test daemon.
# Used by the libp2p/unified-testing hole-punch framework; build context
# is the repository root.

# Stage 1: Build with GHC 9.10
FROM haskell:9.10-slim-bookworm AS builder

WORKDIR /app

COPY hs-libp2p.cabal cabal.project Setup.hs ./

# Fix ppad-sha256 ARM SHA2 intrinsic compilation on Docker (GCC 12).
RUN if [ "$(uname -m)" = "aarch64" ]; then \
      echo 'package ppad-sha256' >> cabal.project && \
      echo '  ghc-options: -optc-march=armv8-a+crypto' >> cabal.project; \
    fi

RUN cabal update && cabal build --only-dependencies lib:hs-libp2p

COPY src/ src/
COPY interop/ interop/
RUN cabal build libp2p-hole-punch \
    && cp "$(cabal list-bin libp2p-hole-punch)" /app/libp2p-hole-punch \
    && strip /app/libp2p-hole-punch

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libgmp10 \
       ca-certificates \
       iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/libp2p-hole-punch /usr/local/bin/libp2p-hole-punch
COPY interop/hole-punch/entrypoint.sh /usr/local/bin/hole-punch-entrypoint
RUN chmod +x /usr/local/bin/hole-punch-entrypoint

ENTRYPOINT ["/usr/local/bin/hole-punch-entrypoint"]
