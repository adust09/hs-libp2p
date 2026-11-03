{- | Tests for the Rendezvous protocol (specs/rendezvous/README.md).

Two layers:

  * deterministic handler tests over "LibP2P.EofStream": the full
    server loop (framing, validation, TTL, limits, cookie
    pagination) in-process with no transport, so every status code
    and the cookie rule are asserted directly;
  * one end-to-end test over real TCP + Noise + Yamux switches:
    three nodes, one acting as the rendezvous point, the other two
    registering and discovering via 'registerSelf' / 'discover'.
-}
module LibP2P.Discovery.RendezvousSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (async, cancel)
import Control.Concurrent.STM (atomically, retry)
import Control.Exception (SomeException, bracket, try)
import Control.Monad (forM_)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Either (isLeft)
import Data.List (sort)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word (Word64)
import LibP2P.Core.Varint (encodeUvarint)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Crypto.PeerRecord (
  PeerRecord (..),
  sealPeerRecord,
  timestampSeq,
 )
import LibP2P.Crypto.SignedEnvelope (encodeSignedEnvelope)
import LibP2P.Discovery.Rendezvous
import LibP2P.Discovery.Rendezvous.Message (
  DiscoverLimit (..),
  RegistrationInfo (..),
  RendezvousMessage (..),
  ResponseStatus (..),
  decodeRendezvousMessage,
  encodeRendezvousMessage,
  maxRendezvousMessageSize,
 )
import LibP2P.EofStream (mkEofStreamPair)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Codec (encodeProtocols)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Switch (addTransport, newSwitch, switchClose)
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Connection, Switch (..))
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

{- | Fast TTLs and tight limits so behaviour (expiry, per-peer limit,
result cap) is observable in milliseconds instead of the spec's
hour-scale defaults.
-}
testConfig :: RendezvousConfig
testConfig =
  RendezvousConfig
    { rcMinTTL = 1
    , rcMaxTTL = 7200
    , rcDefaultTTL = 2
    , rcMaxNamespaceLength = 255
    , rcMaxPerPeer = 2
    , rcMaxResults = 4
    }

-- | A local TCP address for signed records.
localAddr :: Multiaddr
localAddr = Multiaddr [IP4 0x7f000001, TCP 4001]

mkIdentity :: IO (PeerId, KeyPair)
mkIdentity = do
  Right kp <- generateKeyPair
  pure (fromPublicKey (publicKey kp), kp)

-- | Seal a signed peer record (the payload a REGISTER carries).
mkSignedRecord :: KeyPair -> PeerId -> [Multiaddr] -> IO ByteString
mkSignedRecord kp pid addrs = do
  seqNo <- timestampSeq
  let record =
        PeerRecord
          { prPeerId = peerIdBytes pid
          , prSeq = seqNo
          , prAddresses = map (\(Multiaddr ps) -> encodeProtocols ps) addrs
          }
  case sealPeerRecord kp record of
    Left err -> fail err
    Right env -> pure (encodeSignedEnvelope env)

--------------------------------------------------------------------------------
-- Deterministic server harness
--------------------------------------------------------------------------------

{- | A rendezvous point wired to the client half of an in-memory stream
pair. The server side runs 'handleRendezvousStream' in a thread; the
test speaks the wire protocol through 'stClient'. The connection's
peer id (what a switch would have authenticated) is 'stPid'.
-}
data ServerTest = ServerTest
  { stPoint :: RendezvousPoint
  , stClient :: StreamIO
  , stPid :: PeerId
  , stKp :: KeyPair
  }

withRendezvousServer :: (ServerTest -> IO a) -> IO a
withRendezvousServer action = do
  point <- newRendezvousPoint testConfig
  (serverStream, clientStream) <- mkEofStreamPair
  (pid, kp) <- mkIdentity
  bracket
    (async (handleRendezvousStream point serverStream pid))
    cancel
    (\_thread -> action (ServerTest point clientStream pid kp))

{- | Send one request on the client half and read the single framed
reply. Deterministic: queued bytes are drained before EOF, so no
polling or sleeps are needed. UNREGISTER never replies — tests use
'sendUnregister' for it.
-}
sendAndRead ::
  ServerTest -> RendezvousMessage -> IO (Either String RendezvousMessage)
sendAndRead st req = do
  streamWrite (stClient st) (encodeFramedMessage req)
  readFramedMessage (stClient st) maxRendezvousMessageSize

-- | Send an UNREGISTER (no reply expected).
sendUnregister :: ServerTest -> Text -> IO ()
sendUnregister st ns =
  streamWrite (stClient st) (encodeFramedMessage (RMUnregister ns))

-- | Register @stPid@ under a namespace, as the rendezvous client would.
registerSelfAs ::
  ServerTest -> Text -> Maybe Word64 -> IO (Either String RendezvousMessage)
registerSelfAs st ns ttl = do
  record <- mkSignedRecord (stKp st) (stPid st) [localAddr]
  sendAndRead st (RMRegister ns record ttl)

-- | Extract the status of a REGISTER_RESPONSE reply.
replyStatus :: Either String RendezvousMessage -> IO ResponseStatus
replyStatus (Right (RMRegisterResponse s _ _)) = pure s
replyStatus (Right other) = fail ("expected REGISTER_RESPONSE, got: " ++ show other)
replyStatus (Left err) = fail err

{- | Poll until the point's live registration count reaches @expect@,
with a 1s deadline.
-}
waitForCount :: RendezvousPoint -> Int -> IO ()
waitForCount point expect = go (100 :: Int)
 where
  go 0 = fail "waitForCount: registration count never settled"
  go k = do
    current <- registeredCount point
    if current == expect
      then pure ()
      else threadDelay 10000 >> go (k - 1)

-- | Extract the cookie of a successful DISCOVER_RESPONSE.
onlyCookie :: Either String RendezvousMessage -> IO ByteString
onlyCookie (Right (RMDiscoverResponse _ cookie StatusOK _)) = pure cookie
onlyCookie other = fail ("expected DISCOVER_RESPONSE, got: " ++ show other)

--------------------------------------------------------------------------------
-- Codec
--------------------------------------------------------------------------------

codecCases :: [(String, RendezvousMessage)]
codecCases =
  [ ("REGISTER", RMRegister "my-app" "record-bytes" (Just 3600))
  , ("REGISTER without ttl", RMRegister "my-app" "record-bytes" Nothing)
  , ("REGISTER_RESPONSE ok", RMRegisterResponse StatusOK (Just "OK") (Just 7200))
  , ("REGISTER_RESPONSE error", RMRegisterResponse StatusInvalidTTL Nothing Nothing)
  , ("REGISTER_RESPONSE unknown status", RMRegisterResponse (StatusUnknown 123) (Just "future") Nothing)
  , ("UNREGISTER", RMUnregister "my-app")
  , ("DISCOVER", RMDiscover (Just "my-app") LimitDefault "cookie-bytes")
  , ("DISCOVER, all namespaces", RMDiscover Nothing (LimitExact 0) BS.empty)
  ,
    ( "DISCOVER_RESPONSE"
    , RMDiscoverResponse
        [ RegistrationInfo "ns-a" "record-1" 7200
        , RegistrationInfo "ns-b" "record-2" 3600
        ]
        "cookie-bytes"
        StatusOK
        (Just "OK")
    )
  , ("DISCOVER_RESPONSE error", RMDiscoverResponse [] BS.empty StatusInvalidCookie Nothing)
  ]

--------------------------------------------------------------------------------
-- End-to-end helpers over TCP
--------------------------------------------------------------------------------

-- | Wait until the peer appears in the switch's connection pool.
waitForPeerInPool :: Switch -> PeerId -> IO ()
waitForPeerInPool sw pid = do
  seen <- timeout 5000000 $ atomically $ do
    mConn <- lookupConn (swConnPool sw) pid
    maybe retry (const (pure ())) mConn
  case seen of
    Just () -> pure ()
    Nothing -> fail "waitForPeerInPool: peer never appeared in the pool"

{- | A listening switch with a rendezvous point registered, closed on
exit even when the action throws.
-}
withRendezvousNode :: ((Switch, PeerId, Multiaddr) -> IO a) -> IO a
withRendezvousNode action = bracket setup teardown action
 where
  setup = do
    (pid, kp) <- mkIdentity
    sw <- newSwitch pid kp
    tcp <- newTCPTransport
    addTransport sw tcp
    _ <- registerRendezvousPoint sw defaultRendezvousConfig
    addrs <- switchListen sw defaultConnectionGater [Multiaddr [IP4 0x7f000001, TCP 0]]
    addr <- case addrs of
      (a : _) -> pure a
      [] -> fail "withRendezvousNode: listener bound no address"
    pure (sw, pid, addr)
  teardown (sw, _, _) = switchClose sw

-- | A dialing client node, closed on exit even when the action throws.
withClientNode :: ((Switch, PeerId) -> IO a) -> IO a
withClientNode action = bracket setup teardown action
 where
  setup = do
    (pid, kp) <- mkIdentity
    sw <- newSwitch pid kp
    tcp <- newTCPTransport
    addTransport sw tcp
    pure (sw, pid)
  teardown (sw, _) = switchClose sw

-- | Dial a peer and return the connection; fail the test on error.
dialOr :: Switch -> PeerId -> Multiaddr -> IO Connection
dialOr sw peer addr = do
  result <- dial sw peer [addr]
  case result of
    Left err -> fail ("dial failed: " ++ show err)
    Right conn -> do
      waitForPeerInPool sw peer
      pure conn

{- | Decode registrations into discovery events via a queue, the path
an application would consume.
-}
registrationsToEvents :: [RegistrationInfo] -> IO [DiscoveryEvent]
registrationsToEvents regs = do
  queue <- newDiscoveryQueue
  pushDiscoverEvents queue regs
  drainDiscoveryQueue queue

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "Message codec" $ do
    it "roundtrips every message shape through encode/decode" $ do
      forM_ codecCases $ \(_, msg) -> do
        decodeRendezvousMessage (encodeRendezvousMessage msg) `shouldBe` Right msg

    it "rejects an unknown message type discriminator" $ do
      -- type = 99 (0x63), no submessage payload
      decodeRendezvousMessage (BS.pack [0x08, 0x63]) `shouldSatisfy` isLeft

    it "encodes UNREGISTER to the proto2 wire layout from the spec" $ do
      -- Message{type = UNREGISTER, unregister{ns = "app"}}:
      -- field 1 varint 2, field 4 embedded: field 1 string "app"
      encodeRendezvousMessage (RMUnregister "app")
        `shouldBe` BS.pack [0x08, 0x02, 0x22, 0x05, 0x0A, 0x03, 0x61, 0x70, 0x70]

    it "encodes a REGISTER_RESPONSE with status text and ttl" $ do
      -- Message{type = REGISTER_RESPONSE, registerResponse{
      --   status = OK, statusText = "OK", ttl = 3600 }}
      encodeRendezvousMessage (RMRegisterResponse StatusOK (Just "OK") (Just 3600))
        `shouldBe` BS.pack
          [ 0x08, 0x01 -- type REGISTER_RESPONSE
          , 0x1A, 0x09 -- field 3 embedded, 9 bytes
          , 0x08, 0x00 -- status OK
          , 0x12, 0x02, 0x4F, 0x4B -- statusText "OK"
          , 0x18, 0x90, 0x1C -- ttl 3600 varint (3600 = 0b1110_0001_0000)
          ]

    it "framing roundtrips a message through the uvarint length prefix" $ do
      (halfA, halfB) <- mkEofStreamPair
      let msg = RMRegister "app" "record" Nothing
      streamWrite halfA (encodeFramedMessage msg)
      readFramedMessage halfB maxRendezvousMessageSize `shouldReturn` Right msg

    it "framing rejects messages above the size limit before reading" $ do
      (halfA, halfB) <- mkEofStreamPair
      streamWrite halfA (encodeUvarint (fromIntegral (maxRendezvousMessageSize + 1)))
      framingResult <- readFramedMessage halfB maxRendezvousMessageSize
      framingResult `shouldSatisfy` isLeft

  describe "Server: REGISTER" $ do
    it "accepts a self-registration and grants the default TTL" $ do
      withRendezvousServer $ \st -> do
        status <- registerSelfAs st "my-app" Nothing >>= replyStatus
        status `shouldBe` StatusOK

    it "grants the requested TTL when it is within limits" $ do
      withRendezvousServer $ \st -> do
        reply <- registerSelfAs st "my-app" (Just 3600)
        reply `shouldBe` Right (RMRegisterResponse StatusOK (Just "OK") (Just 3600))

    it "clamps a TTL above the maximum to rcMaxTTL" $ do
      withRendezvousServer $ \st -> do
        reply <- registerSelfAs st "my-app" (Just 100000)
        reply `shouldBe` Right (RMRegisterResponse StatusOK (Just "OK") (Just 7200))

    it "rejects a TTL below the minimum with E_INVALID_TTL" $ do
      withRendezvousServer $ \st -> do
        status <- registerSelfAs st "my-app" (Just 0) >>= replyStatus
        status `shouldBe` StatusInvalidTTL

    it "rejects an empty or oversize namespace with E_INVALID_NAMESPACE" $ do
      withRendezvousServer $ \st -> do
        statusEmpty <- registerSelfAs st "" Nothing >>= replyStatus
        statusEmpty `shouldBe` StatusInvalidNamespace
        statusLong <- registerSelfAs st (T.replicate 256 "x") Nothing >>= replyStatus
        statusLong `shouldBe` StatusInvalidNamespace

    it "rejects an undecodable signed peer record with E_INVALID_SIGNED_PEER_RECORD" $ do
      withRendezvousServer $ \st -> do
        status <-
          replyStatus
            =<< sendAndRead st (RMRegister "my-app" "not-an-envelope" Nothing)
        status `shouldBe` StatusInvalidSignedPeerRecord

    it "rejects a record naming a different peer with E_NOT_AUTHORIZED" $ do
      withRendezvousServer $ \st -> do
        -- A valid envelope, but signed for another peer: only the peer
        -- initiating the registration may register itself.
        (otherPid, otherKp) <- mkIdentity
        record <- mkSignedRecord otherKp otherPid [localAddr]
        status <- replyStatus =<< sendAndRead st (RMRegister "my-app" record Nothing)
        status `shouldBe` StatusNotAuthorized

    it "enforces rcMaxPerPeer live registrations across namespaces" $ do
      withRendezvousServer $ \st -> do
        s1 <- replyStatus =<< registerSelfAs st "ns-1" Nothing
        s1 `shouldBe` StatusOK
        s2 <- replyStatus =<< registerSelfAs st "ns-2" Nothing
        s2 `shouldBe` StatusOK
        -- rcMaxPerPeer = 2 live registrations (ns-1, ns-2): the third is refused.
        s3 <- replyStatus =<< registerSelfAs st "ns-3" Nothing
        s3 `shouldBe` StatusNotAuthorized
        -- Re-registering over an existing namespace slot still fits.
        s4 <- replyStatus =<< registerSelfAs st "ns-1" Nothing
        s4 `shouldBe` StatusOK
        count <- registeredCount (stPoint st)
        count `shouldBe` 2

  describe "Server: UNREGISTER" $ do
    it "removes the registration and keeps the stream usable" $ do
      withRendezvousServer $ \st -> do
        _ <- registerSelfAs st "my-app" Nothing
        count1 <- registeredCount (stPoint st)
        count1 `shouldBe` 1
        sendUnregister st "my-app"
        -- UNREGISTER gets no reply, so nothing synchronizes on the
        -- server having applied it: poll (with a deadline) instead of
        -- reading once.
        waitForCount (stPoint st) 0
        -- No reply was sent for UNREGISTER; the stream still serves requests.
        status <- replyStatus =<< registerSelfAs st "my-app" Nothing
        status `shouldBe` StatusOK

    it "treats an unknown namespace as a no-op" $ do
      withRendezvousServer $ \st -> do
        sendUnregister st "never-registered"
        status <- replyStatus =<< registerSelfAs st "my-app" Nothing
        status `shouldBe` StatusOK

  describe "Server: DISCOVER" $ do
    it "returns live registrations with a cookie" $ do
      withRendezvousServer $ \st -> do
        _ <- registerSelfAs st "my-app" (Just 7200)
        reply <- sendAndRead st (RMDiscover (Just "my-app") LimitDefault BS.empty)
        case reply of
          Right (RMDiscoverResponse regs cookie StatusOK _) -> do
            map riNamespace regs `shouldBe` ["my-app"]
            cookie `shouldSatisfy` (not . BS.null)
          _ -> fail ("unexpected DISCOVER response: " ++ show reply)

    it "answers ok with an empty list when nothing is registered" $ do
      withRendezvousServer $ \st -> do
        reply <- sendAndRead st (RMDiscover Nothing LimitDefault BS.empty)
        -- No registration has ever been written: version counter 0, so
        -- the cookie is its 8-byte zero encoding.
        reply
          `shouldBe` Right (RMDiscoverResponse [] (BS.replicate 8 0) StatusOK (Just "OK"))

    it "returns registrations across all namespaces when none is given" $ do
      withRendezvousServer $ \st -> do
        _ <- registerSelfAs st "ns-1" Nothing
        _ <- registerSelfAs st "ns-2" Nothing
        reply <- sendAndRead st (RMDiscover Nothing LimitDefault BS.empty)
        case reply of
          Right (RMDiscoverResponse regs _ StatusOK _) ->
            sort (map riNamespace regs) `shouldBe` ["ns-1", "ns-2"]
          _ -> fail ("unexpected DISCOVER response: " ++ show reply)

    it "restricts to the queried namespace when one is given" $ do
      withRendezvousServer $ \st -> do
        _ <- registerSelfAs st "ns-1" Nothing
        _ <- registerSelfAs st "ns-2" Nothing
        reply <- sendAndRead st (RMDiscover (Just "ns-1") LimitDefault BS.empty)
        case reply of
          Right (RMDiscoverResponse regs _ StatusOK _) ->
            map riNamespace regs `shouldBe` ["ns-1"]
          _ -> fail ("unexpected DISCOVER response: " ++ show reply)

    it "paginates by cookie: new registrations reappear, unchanged ones do not" $ do
      withRendezvousServer $ \st -> do
        r1 <- sendAndRead st (RMDiscover (Just "my-app") LimitDefault BS.empty)
        cookie1 <- onlyCookie r1
        case r1 of
          Right (RMDiscoverResponse [] _ StatusOK _) -> pure ()
          _ -> fail "first discover should return no registrations"
        _ <- registerSelfAs st "my-app" Nothing
        r2 <- sendAndRead st (RMDiscover (Just "my-app") LimitDefault cookie1)
        cookie2 <- onlyCookie r2
        case r2 of
          Right (RMDiscoverResponse regs _ StatusOK _) ->
            map riNamespace regs `shouldBe` ["my-app"]
          _ -> fail ("unexpected second discover: " ++ show r2)
        -- The cookie strictly advances as registrations are written.
        (cookie2 > cookie1) `shouldBe` True
        -- Polling with the newest cookie: nothing new since.
        r3 <- sendAndRead st (RMDiscover (Just "my-app") LimitDefault cookie2)
        case r3 of
          Right (RMDiscoverResponse [] _ StatusOK _) -> pure ()
          _ -> fail ("third discover should be empty: " ++ show r3)

    it "rejects a malformed cookie with E_INVALID_COOKIE" $ do
      withRendezvousServer $ \st -> do
        reply <- sendAndRead st (RMDiscover Nothing LimitDefault "short")
        case reply of
          Right (RMDiscoverResponse _ _ StatusInvalidCookie _) -> pure ()
          _ -> fail ("unexpected response: " ++ show reply)

    it "honours the requested result limit" $ do
      withRendezvousServer $ \st -> do
        _ <- registerSelfAs st "ns-1" Nothing
        _ <- registerSelfAs st "ns-2" Nothing
        r1 <- sendAndRead st (RMDiscover Nothing (LimitExact 1) BS.empty)
        case r1 of
          Right (RMDiscoverResponse regs _ StatusOK _) -> length regs `shouldBe` 1
          _ -> fail ("unexpected response: " ++ show r1)
        r2 <- sendAndRead st (RMDiscover Nothing LimitDefault BS.empty)
        case r2 of
          Right (RMDiscoverResponse regs _ StatusOK _) -> length regs `shouldBe` 2
          _ -> fail ("unexpected response: " ++ show r2)

    it "excludes expired registrations" $ do
      withRendezvousServer $ \st -> do
        _ <- registerSelfAs st "my-app" (Just 1) -- 1s TTL
        count1 <- registeredCount (stPoint st)
        count1 `shouldBe` 1
        threadDelay 1500000 -- 1.5s: the 1s TTL has expired
        count2 <- registeredCount (stPoint st)
        count2 `shouldBe` 0
        reply <- sendAndRead st (RMDiscover Nothing LimitDefault BS.empty)
        case reply of
          Right (RMDiscoverResponse regs _ StatusOK _) -> regs `shouldBe` []
          _ -> fail ("unexpected response: " ++ show reply)

    it "returns records that decode to the registering peer's identity" $ do
      withRendezvousServer $ \st -> do
        _ <- registerSelfAs st "my-app" Nothing
        reply <- sendAndRead st (RMDiscover (Just "my-app") LimitDefault BS.empty)
        case reply of
          Right (RMDiscoverResponse regs _ StatusOK _) -> do
            events <- registrationsToEvents regs
            map discoveryPeerId events `shouldBe` [stPid st]
          _ -> fail ("unexpected DISCOVER response: " ++ show reply)

  describe "Server: stream lifecycle" $ do
    it "ignores a client-sent REGISTER_RESPONSE and keeps serving" $ do
      withRendezvousServer $ \st -> do
        -- A response frame coming from the client side is a protocol
        -- violation; the server must skip it, not kill the stream.
        streamWrite
          (stClient st)
          (encodeFramedMessage (RMRegisterResponse StatusOK (Just "OK") Nothing))
        status <- replyStatus =<< registerSelfAs st "my-app" Nothing
        status `shouldBe` StatusOK

    it "ends the server loop when the client half-closes" $ do
      withRendezvousServer $ \st -> do
        streamClose (stClient st) -- EOF towards the server half
        -- The server loop observes the EOF and tears down; its
        -- closeQuietly turns the client half's reads into an EOF error.
        result <- try (readFramedMessage (stClient st) maxRendezvousMessageSize)
        case result :: Either SomeException (Either String RendezvousMessage) of
          Left _ -> pure () -- EOF, as expected
          Right r -> fail ("expected EOF, read: " ++ show r)

  describe "End-to-end over TCP (three nodes)" $ do
    it "registers, discovers, and unregisters through real switches" $ do
      withRendezvousNode $ \(_swR, pidR, addrR) ->
        withClientNode $ \(swA, pidA) ->
          withClientNode $ \(swC, pidC) -> do
            connA <- dialOr swA pidR addrR
            connC <- dialOr swC pidR addrR

            -- Both clients register in the same namespace.
            grantedA <- registerSelf swA connA "iot" (Just 7200)
            grantedA `shouldBe` Right 7200
            grantedC <- registerSelf swC connC "iot" Nothing
            -- No TTL: the default (2h) is granted.
            grantedC `shouldBe` Right 7200

            -- A discovers everyone in the namespace, itself included.
            foundA <- discover swA connA (Just "iot") LimitDefault BS.empty
            case foundA of
              Right (regs, _cookie) -> do
                map riNamespace regs `shouldMatchList` ["iot", "iot"]
                events <- registrationsToEvents regs
                map discoveryPeerId events `shouldMatchList` [pidA, pidC]
              Left err -> fail ("discover failed: " ++ show err)

            -- C unregisters; it disappears from the next query.
            unregisterSelf swC connC "iot" `shouldReturn` Right ()
            foundA2 <- discover swA connA (Just "iot") LimitDefault BS.empty
            case foundA2 of
              Right (regs, _cookie) -> do
                events <- registrationsToEvents regs
                map discoveryPeerId events `shouldBe` [pidA]
              Left err -> fail ("discover failed: " ++ show err)
