// Kademlia DHT responder for the GET_VALUE round-trip interop check.
//
// An hs publisher PUT_VALUEs a /pk/ record against this go-libp2p Kad-DHT
// responder, and a fresh hs querier GET_VALUEs the same record back. The
// default namespaced validator (pk + ipns) is kept so the responder behaves
// exactly like a stock libp2p node. The Ed25519 seed is pinned so the
// multiaddr composed in docker-compose.kad-dht-go.yml (GO_PEER_ADDR) stays
// valid across builds; the peer's full multiaddr is printed to stdout for
// the CI log.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	ma "github.com/multiformats/go-multiaddr"
)

// roundtripSeed pins the host identity. The peer ID derives from it; update
// GO_PEER_ADDR in docker-compose.kad-dht-go.yml when changing this seed.
var roundtripSeed = [32]byte{
	0x37, 0x39, 0x6c, 0x75, 0x70, 0x71, 0x62, 0x6c, 0x47, 0x72, 0x6e, 0x69,
	0x6c, 0x50, 0x73, 0x71, 0x6c, 0x6c, 0x57, 0x72, 0x6e, 0x69, 0x6c, 0x55,
	0x73, 0x71, 0x6c, 0x42, 0x6c, 0x77, 0x6e, 0x69,
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// libp2p's unmarshaller takes the stdlib 64-byte key (seed plus public half).
	stdKey := ed25519.NewKeyFromSeed(roundtripSeed[:])
	priv, err := crypto.UnmarshalEd25519PrivateKey(stdKey)
	if err != nil {
		return err
	}
	host, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/49001"),
	)
	if err != nil {
		return err
	}
	defer host.Close()
	node, err := dht.New(
		host,
		dht.Mode(dht.ModeServer),
		dht.DisableAutoRefresh(),
	)
	if err != nil {
		return err
	}
	defer node.Close()
	address, err := tcpListenAddress(host.Addrs())
	if err != nil {
		return err
	}
	fmt.Printf("%s/p2p/%s\n", address, host.ID())
	<-ctx.Done()
	return nil
}

// tcpListenAddress picks the /tcp/ listen multiaddr to print.
func tcpListenAddress(addresses []ma.Multiaddr) (ma.Multiaddr, error) {
	for _, addr := range addresses {
		for _, protocol := range addr.Protocols() {
			if protocol.Code == ma.P_TCP {
				return addr, nil
			}
		}
	}
	return nil, fmt.Errorf("no /tcp/ listen address")
}
