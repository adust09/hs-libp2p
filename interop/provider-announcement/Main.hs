module Main (main) where

import Control.Concurrent.Async (wait, withAsync)
import Control.Exception (bracket)
import Control.Monad (unless, void)
import qualified Data.ByteString as BS
import qualified Data.Text as T
import Data.Time (getCurrentTime)
import LibP2P
  ( DHTMode (..), Multiaddr (..), PeerId, Protocol (..), addTransport
  , defaultConnectionGater, dial, fromPublicKey, fromText, generateKeyPair
  , newDHTNode, newSwitch, newTCPTransport, peerIdBytes, provide
  , registerDHTHandler, registerIdentifyHandlers, splitP2P, switchClose, switchListen
  )
import LibP2P.Crypto.Key (publicKey)
import LibP2P.DHT (DHTNode (..), addPeerToTable, stopDHTNode)
import LibP2P.DHT.Distance (peerIdToKey)
import LibP2P.DHT.Message
import LibP2P.DHT.Types (BucketEntry (..), ConnectionType (..))
import System.Environment (getArgs)
import System.Exit (die)
import System.Timeout (timeout)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [address] -> case fromText (T.pack address) >>= splitRemote of
      Left err -> die err
      Right remote -> run remote
    _ -> die "usage: libp2p-provider-check /ip4/127.0.0.1/tcp/PORT/p2p/PEER"
  where
    splitRemote address = case splitP2P address of
      Just remote@(Multiaddr [IP4 0x7f000001, TCP port], _) | port /= 0 -> Right remote
      _ -> Left "expected a loopback TCP address with a nonzero port and peer ID"

run :: (Multiaddr, PeerId) -> IO ()
run (remoteAddress, remotePeer) = do
  keyPair <- generateKeyPair >>= either (const (fail "identity generation failed")) pure
  let localPeer = fromPublicKey (publicKey keyPair)
  bracket (newSwitch localPeer keyPair) switchClose $ \sw -> do
    newTCPTransport >>= addTransport sw
    registerIdentifyHandlers sw
    addresses <- switchListen sw defaultConnectionGater [Multiaddr [IP4 0x7f000001, TCP 0]]
    bracket (newDHTNode sw DHTServer) stopDHTNode $ \node -> do
      registerDHTHandler node
      connected <- bounded (dial sw remotePeer [remoteAddress])
      either (const (fail "could not connect to the remote DHT peer")) (const (pure ())) connected
      now <- getCurrentTime
      void $ addPeerToTable node (BucketEntry remotePeer (peerIdToKey remotePeer)
        [remoteAddress] now Connected)
      bounded (provide node addresses contentKey)
      response <- bounded $ dhtSendRequest node remotePeer
        (emptyDHTMessage { msgType = GetProviders, msgKey = contentKey })
      case response of
        Right message | msgType message == GetProviders ->
          unless (peerIdBytes localPeer `elem` map dhtPeerId (msgProviderPeers message)) $
            fail "remote DHT did not store the provider announcement"
        _ -> fail "GET_PROVIDERS response was missing or misaligned"
      found <- bounded $ dhtSendRequest node remotePeer
        (emptyDHTMessage { msgType = FindNode, msgKey = peerIdBytes remotePeer })
      unless (fmap msgType found == Right FindNode) $
        fail "FIND_NODE response was misaligned after provider publication"
      putStrLn "PASS: provide, GET_PROVIDERS and FIND_NODE against go-libp2p"

bounded :: IO a -> IO a
bounded action = withAsync action $ \worker -> do
  result <- timeout 5000000 (wait worker)
  maybe (fail "DHT operation exceeded five seconds") pure result

contentKey :: BS.ByteString
contentKey = BS.pack [0x12, 0x20] <> BS.replicate 32 0x35
