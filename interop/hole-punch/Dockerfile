# Pin APT to the snapshot used to create the base image. The image digest alone
# does not prevent Debian sid packages from changing between rebuilds.
FROM debian:sid-slim@sha256:5ac67a4d7c0de96e83873e4dd8f7ea3b507ba292fb2cce60a0c3f73322df5cae AS pinned-debian

RUN printf '%s\n' \
       'Types: deb' \
       'URIs: http://snapshot.debian.org/archive/debian/20261027T000000Z' \
       'Suites: sid' \
       'Components: main' \
       'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
       > /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' \
       > /etc/apt/apt.conf.d/99snapshot

# Build in one layer so package caches and object files never enter an image
# layer. This keeps unified-testing's Docker disk usage below hosted-runner limits.
FROM pinned-debian AS builder

WORKDIR /app
COPY hs-libp2p.cabal cabal.project Setup.hs LICENSE ./
COPY src/ src/
COPY test/ test/
COPY interop/ interop/

# The archive is vendored from adust09/quic@912fd264 because Cabal otherwise
# performs a full Git clone for this source-repository-package on every build.
#
# Debian's cabal-install package is periodically rebuilt without a TLS-capable
# transport, which fails `cabal update` with "user error (https not supported)"
# (Interop run 44649762215). Install the ghcup-distributed cabal bindist instead,
# pinned to exact URL and SHA256 for both amd64 and arm64.
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       gcc \
       ghc \
       libc6-dev \
       libgmp-dev \
       make \
       pkg-config \
       xz-utils \
       zlib1g-dev \
    && case "$(uname -m)" in \
         x86_64) \
           CABAL_URL='https://downloads.haskell.org/~ghcup/unofficial-bindists/cabal/3.18.2.0/cabal-install-3.18.2.0-x86_64-linux-glibc.tar.xz' \
           && CABAL_SHA256='f935af858a259806d7fa829d9bb246700775cb489ea75fd07cf16b4f1b234dfc' ;; \
         aarch64) \
           CABAL_URL='https://downloads.haskell.org/~ghcup/unofficial-bindists/cabal/3.18.2.0/cabal-install-3.18.2.0-aarch64-linux-deb11.tar.xz' \
           && CABAL_SHA256='4cd7a3cf0ea2793d2f04db7a96f9743ff423c3fe1eb5e24e6a4638b05d6ef60d' ;; \
         *) echo "unsupported machine: $(uname -m)" >&2 && exit 1 ;; \
       esac \
    && curl --fail --location --silent --show-error --retry 3 \
       --output /tmp/cabal.tar.xz "$CABAL_URL" \
    && echo "$CABAL_SHA256  /tmp/cabal.tar.xz" | sha256sum --check \
    && mkdir /tmp/cabal-unpack \
    && tar --extract --xz --file /tmp/cabal.tar.xz --directory /tmp/cabal-unpack \
    && install /tmp/cabal-unpack/cabal /usr/local/bin/cabal \
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
       xz-utils \
       curl \
       gcc \
       ghc \
       libc6-dev \
       libgmp-dev \
       make \
       pkg-config \
       zlib1g-dev \
    && rm -rf /tmp/cabal-unpack /tmp/cabal.tar.xz /tmp/dist-newstyle /tmp/quic /root/.cache/cabal /var/lib/apt/lists/*

FROM pinned-debian

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
