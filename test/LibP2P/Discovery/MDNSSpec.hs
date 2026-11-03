-- | Tests for mDNS discovery (specs/discovery/mdns.md).
--
-- Two layers:
--
--   * DNS wire-format tests: golden bytes for the find-all-peers
--     question, encode/decode round-trips, name compression (following
--     pointers, rejecting malformed ones), TXT/SRV/unknown rdata;
--   * a service test over loopback multicast: two switches run an
--     mDNS service each and discover one another, addresses included.
module LibP2P.Discovery.MDNSSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket)
import qualified Data.ByteString as BS
import Data.Either (isLeft)
import Data.Foldable (forM_)
import Data.Text (Text)
import qualified Data.Text as T
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Discovery.MDNS
  ( MDNSConfig (..)
  , MDNSService (..)
  , defaultMDNSConfig
  , newMDNSService
  , stopMDNSService
  )
import LibP2P.Discovery.MDNS.Message
  ( DnsPacket (..)
  , DnsQuestion (..)
  , DnsRData (..)
  , DnsRecord (..)
  , classIN
  , decodeDnsPacket
  , encodeDnsPacket
  , typePTR
  , typeSRV
  , typeTXT
  )
import LibP2P.Discovery.Types (DiscoveryEvent (..), drainDiscoveryQueue, tryReadDiscoveryQueue)
import LibP2P.Multiaddr (Multiaddr (..), toText)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Switch (addTransport, newSwitch, switchClose)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Switch (..))
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

--------------------------------------------------------------------------------
-- DNS wire format
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "DNS packet codec" $ do
    it "encodes the find-all-peers question (_p2p._udp.local PTR)" $ do
      let expected =
            BS.pack $
              -- Header: id 0, no flags, QDCOUNT 1, all other counts 0.
              [ 0x00, 0x00 -- id
              , 0x00, 0x00 -- flags: a query
              , 0x00, 0x01 -- QDCOUNT
              , 0x00, 0x00 -- ANCOUNT
              , 0x00, 0x00 -- NSCOUNT
              , 0x00, 0x00 -- ARCOUNT
                -- Question: the service name's labels, then PTR, then IN.
              , 0x04, 0x5F, 0x70, 0x32, 0x70 -- "_p2p"
              , 0x04, 0x5F, 0x75, 0x64, 0x70 -- "_udp"
              , 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C -- "local"
              , 0x00 -- root label
              , 0x00, 0x0C -- type PTR
              , 0x00, 0x01 -- class IN
              ]
          packet = DnsPacket 0 0 [DnsQuestion "_p2p._udp.local" typePTR classIN] [] []
      encodeDnsPacket packet `shouldBe` expected
      decodeDnsPacket expected `shouldBe` Right packet

    it "round-trips an announcement (PTR answer, multi-string TXT additional)" $ do
      let packet =
            DnsPacket
              { pkID = 0
              , pkFlags = 0x8400
              , pkQuestion = []
              , pkAnswer =
                  [ DnsRecord
                      "_p2p._udp.local"
                      typePTR
                      classIN
                      4500
                      (RdPtr "peername._p2p._udp.local")
                  ]
              , pkAdditional =
                  [ DnsRecord
                      "peername._p2p._udp.local"
                      typeTXT
                      classIN
                      4500
                      ( RdTxt
                          [ "dnsaddr=/ip4/192.0.2.0/tcp/4001"
                          , "dnsaddr=/ip6/2001:db8::1/tcp/4001"
                          ]
                      )
                  ]
              }
      decodeDnsPacket (encodeDnsPacket packet) `shouldBe` Right packet

    it "decodes a compressed name (RFC 1035 pointer) and keeps the cursor" $ do
      let raw =
            BS.pack $
              [ 0x00, 0x00 -- id
              , 0x84, 0x00 -- flags: response
              , 0x00, 0x00 -- QDCOUNT
              , 0x00, 0x01 -- ANCOUNT: one PTR
              , 0x00, 0x00 -- NSCOUNT
              , 0x00, 0x01 -- ARCOUNT: one TXT
                -- Answer name, at offset 12: the service name.
              , 0x04, 0x5F, 0x70, 0x32, 0x70, 0x04, 0x5F, 0x75, 0x64, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C
              , 0x00
                -- PTR, class IN, TTL 300, rdata 2 bytes: a pointer back to offset 12
                -- (a PTR whose target is expressed purely by compression).
              , 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x02, 0xC0, 0x0C
                -- Additional: the name is the same pointer; after the 2-byte
                -- pointer the record header continues (the pointer must not
                -- consume it).
              , 0xC0, 0x0C
              , 0x00, 0x10 -- type TXT
              , 0x00, 0x01 -- class IN
              , 0x00, 0x00, 0x00, 0x00 -- TTL 0
              , 0x00, 0x03 -- rdata: 3 bytes
              , 0x02, 0x68, 0x69 -- string "hi"
              ]
      case decodeDnsPacket raw of
        Left err -> fail err
        Right decoded -> do
          pkAnswer decoded
            `shouldBe` [DnsRecord "_p2p._udp.local" typePTR classIN 300 (RdPtr "_p2p._udp.local")]
          pkAdditional decoded
            `shouldBe` [DnsRecord "_p2p._udp.local" typeTXT classIN 0 (RdTxt ["hi"])]

    it "normalizes names to lower case (RFC 6762 §10)" $ do
      let raw =
            BS.pack $
              [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
              , 0x04, 0x5F, 0x50, 0x32, 0x50, 0x04, 0x5F, 0x55, 0x44, 0x50, 0x05, 0x4C, 0x4F, 0x43, 0x41, 0x4C
              , 0x00, 0x00, 0x0C, 0x00, 0x01
              ]
      decodeDnsPacket raw
        `shouldBe` Right
          (DnsPacket 0 0 [DnsQuestion "_p2p._udp.local" typePTR classIN] [] [])

    it "decodes SRV rdata and passes unknown types through as bytes" $ do
      let srvRaw =
            BS.pack $
              [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
                -- name (the service name), then SRV, class IN, TTL 0.
              , 0x04, 0x5F, 0x70, 0x32, 0x70, 0x04, 0x5F, 0x75, 0x64, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C
              , 0x00
              , 0x00, 0x21 -- type SRV
              , 0x00, 0x01
              , 0x00, 0x00, 0x00, 0x00
                -- rdata: prio 0, weight 0, port 4000, target "x._p2p._udp.local"
              , 0x00, 0x19
              , 0x00, 0x00, 0x00, 0x00, 0x0F, 0xA0
              , 0x01, 0x78, 0x04, 0x5F, 0x70, 0x32, 0x70, 0x04, 0x5F, 0x75, 0x64, 0x70, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C
              , 0x00
              ]
      case decodeDnsPacket srvRaw of
        Left err -> fail err
        Right decoded ->
          pkAdditional decoded
            `shouldBe` [DnsRecord "_p2p._udp.local" typeSRV classIN 0 (RdSrv 0 0 4000 "x._p2p._udp.local")]

      let unknownRaw =
            BS.pack $
              [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
              , 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00
              , 0x00, 0x63 -- type 99 (unassigned here)
              , 0x00, 0x01
              , 0x00, 0x00, 0x00, 0x00
              , 0x00, 0x03
              , 0x61, 0x62, 0x63 -- "abc"
              ]
      case decodeDnsPacket unknownRaw of
        Left err -> fail err
        Right decoded ->
          pkAdditional decoded
            `shouldBe` [DnsRecord "local" 99 classIN 0 (RdOther "abc")]

    it "rejects malformed packets: a truncated packet, a forward pointer, a TXT string past rdata" $ do
      decodeDnsPacket BS.empty `shouldSatisfy` isLeft
      -- Name at offset 12 is a compression pointer to offset 64: beyond
      -- the packet and pointing forwards (must be rejected, not looped).
      let forwardPointer =
            [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            , 0xC0, 0x40, 0x00, 0x0C, 0x00, 0x01
            ]
      decodeDnsPacket (BS.pack forwardPointer) `shouldSatisfy` isLeft
      -- TXT record claiming 5 bytes of rdata whose last string is 32 bytes.
      let truncatedTxt =
            [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
            , 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00
            , 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05
            , 0x20, 0x01, 0x02 -- len 32, then 2 bytes
            ]
      decodeDnsPacket (BS.pack truncatedTxt) `shouldSatisfy` isLeft
  specService

--------------------------------------------------------------------------------
-- Service over loopback multicast
--------------------------------------------------------------------------------

-- | Test mDNS configuration: a private service name and port (this
-- instance of the suite is the only user of both), start-up
-- announcements only, and a short spacing so discovery completes in
-- well under a second.
testMdnsConfig :: MDNSConfig
testMdnsConfig =
  defaultMDNSConfig
    { mcServiceName = "_hs-libp2p._udp.local"
    , mcPort = 53531
    , mcAdvertiseInterval = 0
    , mcAnnounceCount = 2
    , mcAnnounceSpacingMs = 20
    , mcBindIPv6 = True -- a stack that cannot open degrades gracefully
    }

mkIdentity :: IO (PeerId, KeyPair)
mkIdentity = do
  Right kp <- generateKeyPair
  pure (fromPublicKey (publicKey kp), kp)

-- | A switch with a loopback listener (so it has addresses to
-- advertise), closed on exit even when the action throws.
withAdvertisedNode :: ((Switch, PeerId) -> IO a) -> IO a
withAdvertisedNode action = bracket setup teardown node
  where
    setup = do
      (pid, kp) <- mkIdentity
      sw <- newSwitch pid kp
      tcp <- newTCPTransport
      addTransport sw tcp
      addrs <- switchListen sw defaultConnectionGater [Multiaddr [IP4 0x7f000001, TCP 0]]
      addr <- case addrs of
        (a : _) -> pure a
        [] -> fail "withAdvertisedNode: listener bound no address"
      pure (sw, pid, addr)
    teardown (sw, _, _) = switchClose sw
    node (sw, pid, _) = action (sw, pid)

-- | Run the mDNS service against a switch for the duration of the
-- action; stop it on every exit path.
withService :: Switch -> (MDNSService -> IO a) -> IO a
withService sw action = do
  result <- newMDNSService sw testMdnsConfig
  case result of
    Left err -> fail err
    Right svc -> do
      outcome <- action svc
      stopMDNSService svc
      pure outcome

-- | Poll the service's queue for up to @seconds@; fail the test if
-- nothing arrives (no sleeps beyond the poll step, so a fast peer
-- passes quickly and a silent one still fails inside the deadline).
waitForDiscovery :: MDNSService -> Int -> IO DiscoveryEvent
waitForDiscovery svc seconds = do
  found <- timeout (seconds * 1000000) poll
  case found of
    Just ev -> pure ev
    Nothing -> fail "waitForDiscovery: no peer discovered in time"
  where
    poll = do
      next <- tryReadDiscoveryQueue (msEvents svc)
      case next of
        Just ev -> pure ev
        Nothing -> threadDelay 20000 >> poll

specService :: Spec
specService =
  describe "mDNS service" $ do
    it "two peers discover each other over loopback multicast" $ do
      withAdvertisedNode $ \(swA, pidA) ->
        withAdvertisedNode $ \(swB, pidB) ->
          withService swA $ \svcA ->
            withService swB $ \svcB -> do
              -- A discovers B, including B's advertised addresses.
              eventAtA <- waitForDiscovery svcA 15
              discoveryPeerId eventAtA `shouldBe` pidB
              discoveryAddrs eventAtA `shouldNotBe` []
              -- The addresses are the listener's (loopback) address.
              forM_ (discoveryAddrs eventAtA) $ \addr ->
                ("/ip4/127.0.0.1" `T.isPrefixOf` toText addr) `shouldBe` True
              -- And B discovers A.
              eventAtB <- waitForDiscovery svcB 15
              discoveryPeerId eventAtB `shouldBe` pidA

    it "never reports itself, even with loopback enabled" $ do
      withAdvertisedNode $ \(swA, pidA) ->
        withService swA $ \svcA -> do
          threadDelay 1500000 -- more than the start-up announce round
          events <- drainDiscoveryQueue (msEvents svcA)
          forM_ events $ \ev -> (discoveryPeerId ev == pidA) `shouldBe` False

    it "starts, stops, and starts again without leaking sockets" $ do
      withAdvertisedNode $ \(swA, _pidA) ->
        bracket
          (do
             result <- newMDNSService swA testMdnsConfig
             case result of
               Right svc -> pure svc
               Left err -> fail err)
          stopMDNSService
          (const (pure ()))