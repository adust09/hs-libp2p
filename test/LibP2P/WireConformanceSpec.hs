-- | Wire-conformance golden vectors (T3b tier, #178).
--
-- Every expected byte string in this module is hand-derived from the
-- upstream specs (multistream-select README, identify/README.md protobuf,
-- kad-dht protobuf, pubsub RPC protobuf, noise payload protobuf) — never
-- from our own encoders. A self-consistent but wrong codec round-trips
-- perfectly through encode/decode tests; it cannot survive a byte-exact
-- fixture derived from the spec.
--
-- Complements the existing byte-exact vectors in Yamux.FrameSpec and the
-- decode-direction go-libp2p-shaped vector in Identify.MessageSpec.
module LibP2P.WireConformanceSpec (spec) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import LibP2P.DHT.Message
  ( DHTMessage (..)
  , DHTPeer (..)
  , MessageType (..)
  , decodeFramed
  , emptyDHTMessage
  , encodeFramed
  )
import LibP2P.DHT.Types (ConnectionType (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , mkByteStreamIO
  , negotiateInitiator
  , negotiateResponder
  )
import LibP2P.MultistreamSelect.Wire (encodeMessage)
import LibP2P.Noise.Handshake (NoisePayload (..), encodeNoisePayload)
import LibP2P.Protocol.GossipSub.Message (encodeRPC)
import LibP2P.Protocol.GossipSub.Types (RPC (..), SubOpts (..))
import LibP2P.Protocol.Identify (encodeFramedIdentify)
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import Test.Hspec

-- | A scripted stream: reads come from a canned byte sequence (recorded
-- from / equivalent to a foreign implementation), writes are captured
-- for byte-exact assertion. Reading past the script raises EOF.
mkScriptedStream :: ByteString -> IO (StreamIO, IO ByteString)
mkScriptedStream canned = do
  writtenRef <- newIORef BS.empty
  readRef <- newIORef canned
  let readB = do
        buf <- readIORef readRef
        case BS.uncons buf of
          Nothing -> ioError (userError "scripted stream: EOF")
          Just (b, rest) -> writeIORef readRef rest >> pure b
      stream = mkByteStreamIO
        (\bs -> modifyIORef' writtenRef (`BS.append` bs))
        readB
        (pure ())
  pure (stream, readIORef writtenRef)

-- | Like 'mkScriptedStream', but additionally snapshots everything the
-- code under test had written at the moment of its FIRST read. Lets a
-- transcript assert pipelining: which bytes were already on the wire
-- before the initiator started waiting for the peer's reply.
mkScriptedStreamSnapshottingFirstRead
  :: ByteString -> IO (StreamIO, IO (Maybe ByteString))
mkScriptedStreamSnapshottingFirstRead canned = do
  writtenRef <- newIORef BS.empty
  readRef <- newIORef canned
  firstReadRef <- newIORef Nothing
  let readB = do
        snapshot <- readIORef firstReadRef
        case snapshot of
          Just _ -> pure ()
          Nothing -> readIORef writtenRef >>= writeIORef firstReadRef . Just
        buf <- readIORef readRef
        case BS.uncons buf of
          Nothing -> ioError (userError "scripted stream: EOF")
          Just (b, rest) -> writeIORef readRef rest >> pure b
      stream = mkByteStreamIO
        (\bs -> modifyIORef' writtenRef (`BS.append` bs))
        readB
        (pure ())
  pure (stream, readIORef firstReadRef)

-- multistream-select vectors (multiformats/multistream-select README:
-- every message is <varint-length><UTF-8 payload>\n, length includes \n).

-- | varint(19) "/multistream/1.0.0" \n
mssHeader :: ByteString
mssHeader = BS.singleton 0x13 <> "/multistream/1.0.0\n"

-- | varint(7) "/noise" \n
mssNoise :: ByteString
mssNoise = BS.singleton 0x07 <> "/noise\n"

-- | varint(13) "/yamux/1.0.0" \n
mssYamux :: ByteString
mssYamux = BS.singleton 0x0d <> "/yamux/1.0.0\n"

-- | varint(3) "na" \n
mssNa :: ByteString
mssNa = BS.singleton 0x03 <> "na\n"

spec :: Spec
spec = do
  describe "multistream-select messages" $ do
    it "header is 0x13 '/multistream/1.0.0' 0x0a" $
      encodeMessage "/multistream/1.0.0" `shouldBe` mssHeader

    it "'/noise' proposal is 0x07 '/noise' 0x0a" $
      encodeMessage "/noise" `shouldBe` mssNoise

    it "'na' rejection is 0x03 'na' 0x0a" $
      encodeMessage "na" `shouldBe` mssNa

  describe "multistream-select transcripts against a scripted foreign peer" $ do
    it "initiator emits exactly header + proposal when the peer accepts" $ do
      (stream, getWritten) <- mkScriptedStream (mssHeader <> mssNoise)
      result <- negotiateInitiator stream ["/noise"]
      result `shouldBe` Accepted "/noise"
      written <- getWritten
      written `shouldBe` mssHeader <> mssNoise

    -- multistream-select README (select flow): "the initiator SHOULD
    -- pipeline the multistream protocol id and the desired protocol id
    -- in the same packet", saving one round trip per negotiation. Both
    -- messages must already be on the wire when the initiator first
    -- blocks on the responder's reply.
    it "initiator pipelines header and first proposal before its first read" $ do
      (stream, getWrittenAtFirstRead) <-
        mkScriptedStreamSnapshottingFirstRead (mssHeader <> mssNoise)
      result <- negotiateInitiator stream ["/noise"]
      result `shouldBe` Accepted "/noise"
      writtenAtFirstRead <- getWrittenAtFirstRead
      writtenAtFirstRead `shouldBe` Just (mssHeader <> mssNoise)

    it "initiator falls back to its second protocol on na" $ do
      (stream, getWritten) <- mkScriptedStream (mssHeader <> mssNa <> mssYamux)
      result <- negotiateInitiator stream ["/noise", "/yamux/1.0.0"]
      result `shouldBe` Accepted "/yamux/1.0.0"
      written <- getWritten
      written `shouldBe` mssHeader <> mssNoise <> mssYamux

    it "responder emits exactly header + echo for a supported proposal" $ do
      (stream, getWritten) <- mkScriptedStream (mssHeader <> mssNoise)
      result <- negotiateResponder stream ["/noise"]
      result `shouldBe` Accepted "/noise"
      written <- getWritten
      written `shouldBe` mssHeader <> mssNoise

    it "responder answers na to an unknown proposal, then accepts a known one" $ do
      let unknown = BS.singleton 0x0b <> "/tls/1.0.0\n"
      (stream, getWritten) <- mkScriptedStream (mssHeader <> unknown <> mssNoise)
      result <- negotiateResponder stream ["/noise"]
      result `shouldBe` Accepted "/noise"
      written <- getWritten
      written `shouldBe` mssHeader <> mssNa <> mssNoise

  describe "identify protobuf (specs/identify/README.md)" $ do
    -- Fields: 1 publicKey, 2 listenAddrs (rep), 3 protocols (rep),
    -- 4 observedAddr, 5 protocolVersion, 6 agentVersion.
    it "framed message matches a hand-derived vector with all fields set" $ do
      let info = IdentifyInfo
            { idProtocolVersion = Just "ipfs/0.1.0"
            , idAgentVersion    = Just "hs-libp2p/0.1.0"
            , idPublicKey       = Just "PK"
            , idListenAddrs     =
                [BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x0f, 0xa1]]
                -- /ip4/127.0.0.1/tcp/4001
            , idObservedAddr    =
                Just (BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x30, 0x39])
                -- /ip4/127.0.0.1/tcp/12345
            , idProtocols       = ["/ipfs/id/1.0.0", "/ipfs/ping/1.0.0"]
            , idSignedPeerRecord = Nothing
            }
          expected = BS.concat
            [ BS.singleton 0x57  -- varint frame length: 87-byte protobuf
            , BS.pack [0x0a, 0x02], "PK"                            -- field 1
            , BS.pack [0x12, 0x08]                                  -- field 2
            , BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x0f, 0xa1]
            , BS.pack [0x1a, 0x0e], "/ipfs/id/1.0.0"                -- field 3
            , BS.pack [0x1a, 0x10], "/ipfs/ping/1.0.0"              -- field 3
            , BS.pack [0x22, 0x08]                                  -- field 4
            , BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x30, 0x39]
            , BS.pack [0x2a, 0x0a], "ipfs/0.1.0"                    -- field 5
            , BS.pack [0x32, 0x0f], "hs-libp2p/0.1.0"               -- field 6
            ]
      encodeFramedIdentify info `shouldBe` expected

  describe "kad-dht protobuf (specs/kad-dht/README.md)" $ do
    it "framed FIND_NODE request matches a hand-derived vector" $ do
      let request = emptyDHTMessage
            { msgType = FindNode
            , msgKey = "some-peer-id"
            }
          expected = BS.concat
            [ BS.singleton 0x10          -- varint frame length: 16
            , BS.pack [0x08, 0x04]       -- field 1 (type): FIND_NODE = 4
            , BS.pack [0x12, 0x0c]       -- field 2 (key): 12 raw bytes
            , "some-peer-id"
            ]
      encodeFramed request `shouldBe` expected

    it "decodes a hand-derived FIND_NODE response with one closerPeer" $ do
      -- Message.Peer: 1 id (bytes), 2 addrs (rep bytes), 3 connection (enum).
      let addrBytes = BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x0f, 0xa1]
          wire = BS.concat
            [ BS.singleton 0x18          -- varint frame length: 24
            , BS.pack [0x08, 0x04]       -- field 1 (type): FIND_NODE = 4
            , BS.pack [0x42, 0x14]       -- field 8 (closerPeers): 20 bytes
            , BS.pack [0x0a, 0x06], "peer-1"
            , BS.pack [0x12, 0x08], addrBytes
            , BS.pack [0x18, 0x01]       -- connection: CONNECTED = 1
            ]
          expected = emptyDHTMessage
            { msgType = FindNode
            , msgCloserPeers =
                [ DHTPeer
                    { dhtPeerId = "peer-1"
                    , dhtPeerAddrs = [addrBytes]
                    , dhtPeerConnType = Connected
                    }
                ]
            }
      decodeFramed 4096 wire `shouldBe` Right expected

  describe "gossipsub RPC protobuf (specs/pubsub/README.md)" $ do
    it "subscription-only RPC matches a hand-derived vector" $ do
      -- RPC: 1 subscriptions (rep SubOpts); SubOpts: 1 subscribe, 2 topicid.
      let rpc = RPC
            { rpcSubscriptions = [SubOpts True "news" False False]
            , rpcPublish = []
            , rpcControl = Nothing
            , rpcPartial = Nothing
            }
          expected = BS.concat
            [ BS.pack [0x0a, 0x08]       -- field 1: 8-byte SubOpts
            , BS.pack [0x08, 0x01]       -- subscribe = true
            , BS.pack [0x12, 0x04]       -- topicid, 4 bytes
            , "news"
            ]
      encodeRPC rpc `shouldBe` expected

  describe "noise handshake payload protobuf (specs/noise/README.md)" $ do
    it "NoiseHandshakePayload matches a hand-derived vector" $ do
      -- Fields: 1 identity_key (bytes), 2 identity_sig (bytes).
      let payload = NoisePayload
            { npIdentityKey = "IDKEY"
            , npIdentitySig = "IDSIG"
            }
          expected = BS.concat
            [ BS.pack [0x0a, 0x05], "IDKEY"
            , BS.pack [0x12, 0x05], "IDSIG"
            ]
      encodeNoisePayload payload `shouldBe` expected
