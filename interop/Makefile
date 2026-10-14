# Makefile for local interop test runs.
# hs-libp2p speaks the libp2p/unified-testing "modern" transport contract;
# the go-libp2p cross tests go through the legacy key-translation shims
# defined in docker-compose.cross.yml.

IMAGE_NAME := hs-libp2p-interop

.PHONY: build image self-test cross-test-go-listener cross-test-hs-listener \
        cross-test-tls-go-listener cross-test-tls-hs-listener \
        cross-gossipsub-rust-listener cross-gossipsub-hs-listener cross-gossipsub kad-dht \
        perf-self-test perf-cross-nim-listener perf-cross-hs-listener perf-cross nim-libp2p \
        hole-punch-self-test

# nim-libp2p commit pinned by unified-testing perf/images.yaml (nim-v1.15).
NIM_LIBP2P_COMMIT := 1bdf2f67971529e8bee01252230bdb00ab785ef7

image:
	docker build -t $(IMAGE_NAME) ..

build: image

# Self-test: hs listener + hs dialer
self-test:
	cd .. && docker compose up --build --exit-code-from dialer redis listener dialer

# kad-dht self-test: hs bootstrap -> hs provider -> hs querier
kad-dht:
	cd .. && docker compose -f docker-compose.kad-dht.yml up --build --exit-code-from querier redis bootstrap provider querier

# Cross-test: go listener, hs dialer (key-translation shim starts via depends_on)
cross-test-go-listener:
	cd .. && docker compose -f docker-compose.cross.yml up --build --exit-code-from hs-dialer redis go-listener hs-dialer

# Cross-test: hs listener, go dialer (key-translation shim starts via depends_on)
cross-test-hs-listener:
	cd .. && docker compose -f docker-compose.cross.yml up --build --exit-code-from go-dialer redis hs-listener go-dialer

# TLS cross-test: go listener, hs dialer
cross-test-tls-go-listener:
	cd .. && docker compose -f docker-compose.cross.yml -f docker-compose.tls-cross.yml up --build --exit-code-from hs-dialer redis go-listener hs-dialer

# TLS cross-test: hs listener, go dialer
cross-test-tls-hs-listener:
	cd .. && docker compose -f docker-compose.cross.yml -f docker-compose.tls-cross.yml up --build --exit-code-from go-dialer redis hs-listener go-dialer

# GossipSub cross-test: rust listener, hs dialer
cross-gossipsub-rust-listener:
	cd .. && docker compose -f docker-compose.gossipsub.yml up --build --exit-code-from hs-dialer redis rust-listener hs-dialer

# GossipSub cross-test: hs listener, rust dialer
cross-gossipsub-hs-listener:
	cd .. && docker compose -f docker-compose.gossipsub.yml up --build --exit-code-from rust-dialer redis hs-listener rust-dialer

# GossipSub cross-test: both directions
cross-gossipsub: cross-gossipsub-rust-listener cross-gossipsub-hs-listener

# Perf self-test: hs listener + hs dialer
perf-self-test:
	cd .. && docker compose -f docker-compose.perf.yml up --build --exit-code-from hs-perf-dialer redis hs-perf-listener hs-perf-dialer

# Clone nim-libp2p at the commit unified-testing pins for perf (nim-v1.15)
nim-libp2p:
	cd .. && test -d nim-libp2p || git clone https://github.com/vacp2p/nim-libp2p.git nim-libp2p
	cd ../nim-libp2p && git checkout $(NIM_LIBP2P_COMMIT)

# Perf cross-test: nim listener, hs dialer
perf-cross-nim-listener: nim-libp2p
	cd .. && docker compose -f docker-compose.perf-cross.yml up --build --exit-code-from hs-perf-dialer redis nim-perf-listener hs-perf-dialer

# Perf cross-test: hs listener, nim dialer
perf-cross-hs-listener: nim-libp2p
	cd .. && docker compose -f docker-compose.perf-cross.yml up --build --exit-code-from nim-perf-dialer redis hs-perf-listener nim-perf-dialer

# Perf cross-test: both directions
perf-cross: perf-cross-nim-listener perf-cross-hs-listener

# Hole-punch self-test: hs peers behind separate NAT routers with a WAN relay
hole-punch-self-test:
	cd .. && docker compose -f docker-compose.hole-punch.yml up --build \
		--exit-code-from hs-hp-dialer redis dialer-router listener-router \
		hs-hp-relay hs-hp-listener hs-hp-dialer
