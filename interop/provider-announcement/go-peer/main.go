package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		return err
	}
	defer host.Close()
	node, err := dht.New(host, dht.Mode(dht.ModeServer), dht.DisableAutoRefresh())
	if err != nil {
		return err
	}
	defer node.Close()
	addresses := host.Addrs()
	if len(addresses) == 0 {
		return fmt.Errorf("no loopback listen address")
	}
	fmt.Printf("%s/p2p/%s\n", addresses[0], host.ID())
	<-ctx.Done()
	return nil
}
