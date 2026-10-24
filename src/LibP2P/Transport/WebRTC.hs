-- | libp2p WebRTC Direct and relay-signaled transports.
module LibP2P.Transport.WebRTC (
  STUNServer (..),
  WebRTCConfig (..),
  defaultWebRTCConfig,
  webRTCDirectTransport,
  webRTCTransport,
  canDialWebRTCDirect,
  canDialWebRTC,
  buildWebRTCNoisePrologue,
) where

import LibP2P.Transport.WebRTC.Direct (
  buildWebRTCNoisePrologue,
  canDialWebRTCDirect,
  webRTCDirectTransport,
 )
import LibP2P.Transport.WebRTC.Relay (
  STUNServer (..),
  WebRTCConfig (..),
  canDialWebRTC,
  defaultWebRTCConfig,
  webRTCTransport,
 )
