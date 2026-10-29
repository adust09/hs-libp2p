# Build in one layer so package caches and object files never enter an image
# layer. This keeps unified-testing's Docker disk usage below hosted-runner limits.
FROM debian:sid-slim@sha256:5ac67a4d7c0de96e83873e4dd8f7ea3b507ba292fb2cce60a0c3f73322df5cae AS builder

WORKDIR /app
COPY hs-libp2p.cabal cabal.project Setup.hs LICENSE ./
COPY src/ src/
COPY test/ test/
COPY interop/ interop/

# The archive is vendored from adust09/quic@912fd264 because Cabal otherwise
# performs a full Git clone for this source-repository-package on every build.
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       cabal-install \
       ca-certificates \
       gcc \
       ghc \
       libc6-dev \
       libgmp-dev \
       make \
       pkg-config \
       zlib1g-dev \
    && echo 'ba80ede048516e9aad9716137751a7d75014d9f9eb48526c0df6e3b90f89116c  interop/hole-punch/vendor/quic-912fd264.tar.gz' | sha256sum --check \
    && mkdir /tmp/quic \
    && tar --extract --gzip --file interop/hole-punch/vendor/quic-912fd264.tar.gz --directory /tmp/quic --strip-components=1 \
    && printf 'packages: /app /tmp/quic\ntests: True\n' > /tmp/cabal.project \
    && if [ "$(uname -m)" = "aarch64" ]; then \
         echo 'package ppad-sha256' >> /tmp/cabal.project; \
         echo '  ghc-options: -optc-march=armv8-a+crypto' >> /tmp/cabal.project; \
       fi \
    && cd /tmp \
    && cabal update \
    && cabal build libp2p-hole-punch \
       --disable-library-for-ghci \
       --disable-optimization \
       --disable-shared \
    && mkdir -p /out \
    && cp "$(cabal list-bin libp2p-hole-punch \
       --disable-library-for-ghci \
       --disable-optimization \
       --disable-shared)" /out/libp2p-hole-punch \
    && apt-get purge -y --auto-remove \
       cabal-install \
       gcc \
       ghc \
       libc6-dev \
       libgmp-dev \
       make \
       pkg-config \
       zlib1g-dev \
    && rm -rf /tmp/dist-newstyle /tmp/quic /root/.cache/cabal /var/lib/apt/lists/*

FROM debian:sid-slim@sha256:5ac67a4d7c0de96e83873e4dd8f7ea3b507ba292fb2cce60a0c3f73322df5cae

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       iproute2 \
       libffi8 \
       libgmp10 \
       libnuma1 \
       zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/libp2p-hole-punch /usr/local/bin/libp2p-hole-punch
COPY interop/hole-punch/entrypoint.sh /usr/local/bin/hole-punch-entrypoint
RUN chmod +x /usr/local/bin/hole-punch-entrypoint

ENTRYPOINT ["/usr/local/bin/hole-punch-entrypoint"]
