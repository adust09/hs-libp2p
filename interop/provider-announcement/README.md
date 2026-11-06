# Provider announcement interoperability

Verify that Haskell `provide` returns against a real go-libp2p DHT, then read the
provider back with GET_PROVIDERS and issue FIND_NODE on the same cached stream.
The Go node uses the upstream handler, which sends no ADD_PROVIDER response.

Requires Go 1.26+, GHC 9.10.x and Cabal. Build the Haskell library first:

```sh
cabal build all
```

Start the Go DHT in one terminal (leave it running):

```sh
cd interop/provider-announcement/go-peer
go run .
```

Copy its printed `/ip4/127.0.0.1/tcp/.../p2p/...` address. From the repository
root, run in a second terminal:

```sh
cabal run libp2p-provider-check -- \
  /ip4/127.0.0.1/tcp/PORT/p2p/PEER
```

Success prints `PASS: provide, GET_PROVIDERS and FIND_NODE against go-libp2p`.
Dialing and each DHT operation have a five-second deadline. Stop the Go process with
Ctrl-C after the check. All traffic remains on loopback.
