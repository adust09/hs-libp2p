module LibP2P.Switch.ResourceManagerSpec (spec) where

import Control.Concurrent.STM (atomically, readTVar)
import Control.Exception (SomeException, try)
import qualified Data.Map.Strict as Map
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Switch.ResourceManager
import Test.Hspec

peerA, peerB :: PeerId
peerA = PeerId "peer-a-rm"
peerB = PeerId "peer-b-rm"

testDefaults :: DefaultLimits
testDefaults = DefaultLimits
  { dlSystemLimits = noLimits
      { rlMaxConnsInbound = Just 4
      , rlMaxConnsOutbound = Just 4
      , rlMaxConnsTotal = Just 6
      , rlMaxStreamsInbound = Just 8
      , rlMaxStreamsOutbound = Just 8
      , rlMaxStreamsTotal = Just 12
      , rlMaxMemory = Just 4096
      }
  , dlPeerLimits = noLimits
      { rlMaxConnsInbound = Just 2
      , rlMaxConnsOutbound = Just 2
      , rlMaxConnsTotal = Just 3
      , rlMaxStreamsInbound = Just 4
      , rlMaxStreamsOutbound = Just 4
      , rlMaxStreamsTotal = Just 6
      , rlMaxMemory = Just 2048
      }
  , dlConnectionLimits = noLimits {rlMaxMemory = Just 1024}
  , dlStreamLimits = noLimits {rlMaxMemory = Just 512}
  }

reserveConn :: ResourceManager -> PeerId -> Direction -> IO ResourceScope
reserveConn rm pid dir = do
  result <- atomically $ reserveConnection rm pid dir
  case result of
    Right scope -> pure scope
    Left err -> expectationFailure (show err) >> error "unreachable"

reserveStr :: ResourceManager -> ResourceScope -> Direction -> IO ResourceScope
reserveStr rm conn dir = do
  result <- atomically $ reserveStream rm conn dir
  case result of
    Right scope -> pure scope
    Left err -> expectationFailure (show err) >> error "unreachable"

usageOf :: ResourceScope -> IO ResourceUsage
usageOf = atomically . readTVar . rsUsage

peerScopeCount :: ResourceManager -> IO Int
peerScopeCount rm = Map.size <$> atomically (readTVar (rmPeerScopes rm))

spec :: Spec
spec = do
  describe "scope hierarchy" $ do
    it "should create System -> Peer -> Connection -> Stream scopes" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Outbound
      rsName conn `shouldSatisfy` isConnectionScope
      rsName stream `shouldSatisfy` isStreamScope
      fmap rsName (rsParent conn) `shouldBe` Just (PeerScope peerA)
      fmap rsName (rsParent stream) `shouldBe` Just (rsName conn)

    it "should apply connection and stream default limits to child scopes" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Inbound
      rsLimits conn `shouldBe` dlConnectionLimits testDefaults
      rsLimits stream `shouldBe` dlStreamLimits testDefaults

    it "should assign distinct scope IDs to sibling connections and streams" $ do
      rm <- newResourceManager testDefaults
      connA <- reserveConn rm peerA Outbound
      connB <- reserveConn rm peerA Outbound
      streamA <- reserveStr rm connA Outbound
      streamB <- reserveStr rm connA Outbound
      rsName connA `shouldNotBe` rsName connB
      rsName streamA `shouldNotBe` rsName streamB

  describe "count reservations" $ do
    it "should propagate connection and stream counts to every ancestor" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Outbound
      connUsage <- usageOf conn
      peer <- atomically $ getOrCreatePeerScope rm peerA
      peerUsage <- usageOf peer
      systemUsage <- usageOf (rmSystemScope rm)
      ruConnsInbound connUsage `shouldBe` 1
      ruStreamsOutbound connUsage `shouldBe` 1
      ruStreamsOutbound <$> usageOf stream `shouldReturn` 1
      peerUsage `shouldBe` systemUsage

    it "should reject a child reserve when the peer connection limit is exceeded" $ do
      rm <- newResourceManager testDefaults
      _ <- reserveConn rm peerA Inbound
      _ <- reserveConn rm peerA Inbound
      result <- atomically $ reserveConnection rm peerA Inbound
      isPeerLimitError result `shouldBe` True

    it "should reject a child reserve when the system limit is exceeded" $ do
      rm <- newResourceManager testDefaults
      _ <- reserveConn rm peerA Inbound
      _ <- reserveConn rm peerA Inbound
      _ <- reserveConn rm peerB Inbound
      _ <- reserveConn rm peerB Inbound
      result <- atomically $ reserveConnection rm (PeerId "peer-c-rm") Inbound
      isSystemLimitError result `shouldBe` True

    it "should not leave phantom usage or an empty peer after a failed reserve" $ do
      let limits = testDefaults
            { dlSystemLimits = (dlSystemLimits testDefaults)
                {rlMaxConnsTotal = Just 0}
            }
      rm <- newResourceManager limits
      result <- atomically $ reserveConnection rm peerA Inbound
      isSystemLimitError result `shouldBe` True
      usageOf (rmSystemScope rm) `shouldReturn` emptyUsage
      peerScopeCount rm `shouldReturn` 0

  describe "memory accounting" $ do
    it "should reserve memory from a stream through the full ancestor chain" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Inbound
      atomically (reserveMemory stream 256) `shouldReturn` Right ()
      peer <- atomically $ getOrCreatePeerScope rm peerA
      mapM usageOf [stream, conn, peer, rmSystemScope rm]
        `shouldReturn`
          [ ResourceUsage 0 0 1 0 256
          , ResourceUsage 1 0 1 0 256
          , ResourceUsage 1 0 1 0 256
          , ResourceUsage 1 0 1 0 256
          ]

    it "should fail atomically when a memory limit is exceeded" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Inbound
      atomically (reserveMemory stream 512) `shouldReturn` Right ()
      result <- atomically $ reserveMemory stream 1
      result `shouldBe` Left (ResourceLimitExceeded (rsName stream) "memory")
      ruMemory <$> usageOf stream `shouldReturn` 512
      ruMemory <$> usageOf conn `shouldReturn` 512

    it "should release reserved memory back to zero" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Inbound
      atomically $ do
        _ <- reserveMemory stream 300
        releaseMemory stream 300
      ruMemory <$> usageOf stream `shouldReturn` 0
      ruMemory <$> usageOf conn `shouldReturn` 0

    it "should reject non-positive memory reservations" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      atomically (reserveMemory conn 0)
        `shouldReturn` Left (InvalidMemoryReservation 0)
      atomically (reserveMemory conn (-1))
        `shouldReturn` Left (InvalidMemoryReservation (-1))

  describe "scope release and peer garbage collection" $ do
    it "should release a stream exactly once" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Outbound
      atomically $ releaseStream rm stream
      atomically $ releaseStream rm stream
      connUsage <- usageOf conn
      ruStreamsOutbound connUsage `shouldBe` 0
      atomically (readTVar (rsClosed stream)) `shouldReturn` True

    it "should recursively close child streams and release their memory" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Inbound
      _ <- atomically $ reserveMemory stream 400
      atomically $ releaseConnection rm conn
      usageOf (rmSystemScope rm) `shouldReturn` emptyUsage
      atomically (readTVar (rsClosed conn)) `shouldReturn` True
      atomically (readTVar (rsClosed stream)) `shouldReturn` True
      atomically (releaseMemory stream 400)
      usageOf (rmSystemScope rm) `shouldReturn` emptyUsage

    it "should retain a peer scope until its final connection closes" $ do
      rm <- newResourceManager testDefaults
      connA <- reserveConn rm peerA Inbound
      connB <- reserveConn rm peerA Outbound
      atomically $ releaseConnection rm connA
      peerScopeCount rm `shouldReturn` 1
      atomically $ releaseConnection rm connB
      peerScopeCount rm `shouldReturn` 0

    it "should drop a peer after its final connection and stream are released" $ do
      rm <- newResourceManager testDefaults
      conn <- reserveConn rm peerA Inbound
      stream <- reserveStr rm conn Inbound
      atomically $ releaseStream rm stream
      peerScopeCount rm `shouldReturn` 1
      atomically $ releaseConnection rm conn
      peerScopeCount rm `shouldReturn` 0

  describe "bracket helpers" $ do
    it "should release a connection and its children after an exception" $ do
      rm <- newResourceManager testDefaults
      _ <- try @SomeException $ withConnection rm peerA Inbound $ \conn -> do
        withStream rm conn Inbound $ \stream -> do
          atomically (reserveMemory stream 100) >>= either (fail . show) pure
          error "boom"
      usageOf (rmSystemScope rm) `shouldReturn` emptyUsage
      peerScopeCount rm `shouldReturn` 0

  describe "defaults" $ do
    it "should preserve advertised system and peer memory limits" $ do
      rlMaxMemory defaultSystemLimits `shouldBe` Just (256 * 1024 * 1024)
      rlMaxMemory defaultPeerLimits `shouldBe` Just (16 * 1024 * 1024)

    it "should leave child-specific defaults unlimited" $ do
      defaultConnectionLimits `shouldBe` noLimits
      defaultStreamLimits `shouldBe` noLimits

isConnectionScope :: ScopeName -> Bool
isConnectionScope (ConnectionScope _) = True
isConnectionScope _ = False

isStreamScope :: ScopeName -> Bool
isStreamScope (StreamScope _) = True
isStreamScope _ = False

isPeerLimitError :: Either ResourceError a -> Bool
isPeerLimitError (Left (ResourceLimitExceeded (PeerScope _) _)) = True
isPeerLimitError _ = False

isSystemLimitError :: Either ResourceError a -> Bool
isSystemLimitError (Left (ResourceLimitExceeded SystemScope _)) = True
isSystemLimitError _ = False
