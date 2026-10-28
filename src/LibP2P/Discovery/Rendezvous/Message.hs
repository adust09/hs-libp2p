{- | Rendezvous protocol messages (specs/rendezvous/README.md).

Wire format (specs/rendezvous/README.md §Protobuf, proto2):

> message Message {
>   enum MessageType { REGISTER = 0; REGISTER_RESPONSE = 1;
>                      UNREGISTER = 2; DISCOVER = 3; DISCOVER_RESPONSE = 4; }
>   enum ResponseStatus { OK = 0; E_INVALID_NAMESPACE = 100;
>                         E_INVALID_SIGNED_PEER_RECORD = 101; E_INVALID_TTL = 102;
>                         E_INVALID_COOKIE = 103; E_NOT_AUTHORIZED = 200;
>                         E_INTERNAL_ERROR = 300; E_UNAVAILABLE = 400; }
>   message Register        { optional string ns = 1; optional bytes
>                             signedPeerRecord = 2; optional uint64 ttl = 3; }
>   message RegisterResponse{ optional ResponseStatus status = 1;
>                             optional string statusText = 2;
>                             optional uint64 ttl = 3; }
>   message Unregister      { optional string ns = 1; }
>   message Discover        { optional string ns = 1; optional uint64 limit = 2;
>                             optional bytes cookie = 3; }
>   message DiscoverResponse{ repeated Register registrations = 1;
>                             optional bytes cookie = 2;
>                             optional ResponseStatus status = 3;
>                             optional string statusText = 4; }
>   optional MessageType type = 1;
>   optional Register register = 2; ... DiscoverResponse discoverResponse = 6;
> }

Uses proto3-wire for protobuf encoding/decoding. On the wire the
message is varint-length-delimited; the framing lives in
"LibP2P.Discovery.Rendezvous" (encodeFramedMessage / readFramedMessage).
-}
module LibP2P.Discovery.Rendezvous.Message (
  -- * Message types
  RendezvousMessage (..),
  RegistrationInfo (..),
  ResponseStatus (..),
  DiscoverLimit (..),

  -- * Codec
  encodeRendezvousMessage,
  decodeRendezvousMessage,
  maxRendezvousMessageSize,
) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BL
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Lazy qualified as TL
import Data.Word (Word64)
import Proto3.Wire.Decode (
  ParseError,
  Parser,
  RawMessage,
  at,
  embedded,
  embedded',
  one,
  optional,
  parse,
  repeated,
 )
import Proto3.Wire.Decode qualified as Decode
import Proto3.Wire.Encode (MessageBuilder)
import Proto3.Wire.Encode qualified as Encode
import Proto3.Wire.Types (FieldNumber (..))

fn :: Int -> FieldNumber
fn = FieldNumber . fromIntegral

{- | Maximum rendezvous message size: 1 MiB. Signed peer records are a
few hundred bytes; registrations are bounded by the discovery limits
(1000 per query by recommendation), so 1 MiB is far above anything
legitimate. Rejecting larger messages before reading the payload
keeps a hostile peer from pinning memory.
-}
maxRendezvousMessageSize :: Int
maxRendezvousMessageSize = 1024 * 1024

-- | Response status codes (specs/rendezvous/README.md §Protobuf).
data ResponseStatus
  = StatusOK
  | StatusInvalidNamespace
  | StatusInvalidSignedPeerRecord
  | StatusInvalidTTL
  | StatusInvalidCookie
  | StatusNotAuthorized
  | StatusInternalError
  | StatusUnavailable
  | -- | Unrecognized code; preserved for forward compat
    StatusUnknown !Word64
  deriving (Show, Eq)

responseStatusCode :: ResponseStatus -> Word64
responseStatusCode s = case s of
  StatusOK -> 0
  StatusInvalidNamespace -> 100
  StatusInvalidSignedPeerRecord -> 101
  StatusInvalidTTL -> 102
  StatusInvalidCookie -> 103
  StatusNotAuthorized -> 200
  StatusInternalError -> 300
  StatusUnavailable -> 400
  StatusUnknown c -> c

responseStatusFromCode :: Word64 -> ResponseStatus
responseStatusFromCode code = case code of
  0 -> StatusOK
  100 -> StatusInvalidNamespace
  101 -> StatusInvalidSignedPeerRecord
  102 -> StatusInvalidTTL
  103 -> StatusInvalidCookie
  200 -> StatusNotAuthorized
  300 -> StatusInternalError
  400 -> StatusUnavailable
  c -> StatusUnknown c

{- | One registration as carried in a DISCOVER response: the namespace
it was registered under, its signed peer record (RFC 0003 envelope),
and the TTL it was registered with.
-}
data RegistrationInfo = RegistrationInfo
  { riNamespace :: !Text
  -- ^ Namespace the peer registered under
  , riPeerRecord :: !ByteString
  -- ^ Encoded signed peer-record envelope
  , riTTL :: !Word64
  -- ^ Registration TTL in seconds
  }
  deriving (Show, Eq)

{- | Discovery limit: absent (rendezvous point default applies) or an
explicit maximum (possibly 0). Both are meaningful on the wire: a
rendezvous point with zero registrations to hand out still answers
OK with an empty list, so an absent limit must not be conflated with
"zero".
-}
data DiscoverLimit
  = -- | No limit given; rendezvous point applies its default
    LimitDefault
  | -- | Explicit limit, possibly 0
    LimitExact !Word64
  deriving (Show, Eq)

{- | A rendezvous message (specs/rendezvous/README.md §Protobuf).

The five wire message types are separate constructors; the envelope
@type@ discriminator (field 1) is checked on decode and set on
encode, so a decoded message never disagrees with its type field.
-}
data RendezvousMessage
  = {- | A @REGISTER@: namespace, signed peer-record envelope (RFC
    0003), requested TTL (absent = rendezvous point default).
    -}
    RMRegister !Text !ByteString !(Maybe Word64)
  | {- | A @REGISTER_RESPONSE@: grant or rejection status, optional
    status text, granted TTL (present when the registration was OK).
    -}
    RMRegisterResponse !ResponseStatus !(Maybe Text) !(Maybe Word64)
  | -- | An @UNREGISTER@: namespace to cancel in.
    RMUnregister !Text
  | {- | A @DISCOVER@: namespace ('Nothing' or empty = ask for every
    namespace), result limit, previous response cookie.
    -}
    RMDiscover !(Maybe Text) !DiscoverLimit !ByteString
  | {- | A @DISCOVER_RESPONSE@: current registrations, cookie for the
    next poll, status, optional status text.
    -}
    RMDiscoverResponse ![RegistrationInfo] !ByteString !ResponseStatus !(Maybe Text)
  deriving (Show, Eq)

messageTypeOf :: RendezvousMessage -> Word64
messageTypeOf msg = case msg of
  RMRegister{} -> 0
  RMRegisterResponse{} -> 1
  RMUnregister{} -> 2
  RMDiscover{} -> 3
  RMDiscoverResponse{} -> 4

{- | Encode a rendezvous message to protobuf wire format. The message
type (field 1) is always written; exactly one submessage (fields
2-6) is written, matching the discriminator. Submessage fields that
coincide with a proto3 default (empty bytes, status OK code 0) are
written explicitly where the spec's response semantics need them
(status, ttl), matching go-libp2p's encoder, and omitted elsewhere.
-}
encodeRendezvousMessage :: RendezvousMessage -> ByteString
encodeRendezvousMessage msg =
  BL.toStrict $
    Encode.toLazyByteString $
      Encode.uint32 (fn 1) (fromIntegral (messageTypeOf msg))
        <> case msg of
          RMRegister ns rec ttl ->
            Encode.embedded (fn 2) $
              fieldText (fn 1) ns <> fieldBytes (fn 2) rec <> optUint64 (fn 3) ttl
          RMRegisterResponse status text ttl ->
            Encode.embedded (fn 3) $
              Encode.uint64 (fn 1) (responseStatusCode status)
                <> optText (fn 2) text
                <> optUint64 (fn 3) ttl
          RMUnregister ns ->
            Encode.embedded (fn 4) $
              fieldText (fn 1) ns
          RMDiscover ns limit cookie ->
            Encode.embedded (fn 5) $
              optText (fn 1) ns <> limitField (fn 2) limit <> fieldBytes (fn 3) cookie
          RMDiscoverResponse regs cookie status text ->
            Encode.embedded (fn 6) $
              foldMap (Encode.embedded (fn 1) . encodeRegistration) regs
                <> fieldBytes (fn 2) cookie
                <> Encode.uint64 (fn 3) (responseStatusCode status)
                <> optText (fn 4) text

encodeRegistration :: RegistrationInfo -> MessageBuilder
encodeRegistration ri =
  fieldText (fn 1) (riNamespace ri)
    <> fieldBytes (fn 2) (riPeerRecord ri)
    <> Encode.uint64 (fn 3) (riTTL ri)

{- | An absent @limit@ is omitted; an explicit value — including 0 —
is written so the rendezvous point can tell the two apart.
-}
limitField :: FieldNumber -> DiscoverLimit -> MessageBuilder
limitField _ LimitDefault = mempty
limitField num (LimitExact n) = Encode.uint64 num n

-- Encode helpers --------------------------------------------------------------

{- | Write a text field, omitting the empty string (a proto2 optional
that was not set). The empty namespace in a DISCOVER question means
"all peers", and the wire omission is how it is expressed.
-}
fieldText :: FieldNumber -> Text -> MessageBuilder
fieldText f t
  | T.null t = mempty
  | otherwise = Encode.text f (TL.fromStrict t)

optText :: FieldNumber -> Maybe Text -> MessageBuilder
optText _ Nothing = mempty
optText f (Just t) = Encode.text f (TL.fromStrict t)

fieldBytes :: FieldNumber -> ByteString -> MessageBuilder
fieldBytes f bs
  | BS.null bs = mempty
  | otherwise = Encode.byteString f bs

optUint64 :: FieldNumber -> Maybe Word64 -> MessageBuilder
optUint64 _ Nothing = mempty
optUint64 f (Just n) = Encode.uint64 f n

-- Decode ----------------------------------------------------------------------

{- | Decode a rendezvous message from protobuf wire format.

The type discriminator (field 1) selects which submessage shape is
parsed; a message whose discriminator names no known type is a
decode error rather than a partial guess.
-}
decodeRendezvousMessage :: ByteString -> Either ParseError RendezvousMessage
decodeRendezvousMessage = parse rendezvousParser

{- | The type discriminator (field 1) selects which submessage (fields
2-6) is parsed; a missing submessage or an unknown discriminator is
a decode error rather than a partial guess.
-}
rendezvousParser :: Parser RawMessage RendezvousMessage
rendezvousParser = do
  mtype <- at (one Decode.uint32 0) (fn 1)
  case mtype of
    0 -> requireSub 2 registerParser
    1 -> requireSub 3 registerResponseParser
    2 -> requireSub 4 unregisterParser
    3 -> requireSub 5 discoverParser
    4 -> requireSub 6 discoverResponseParser
    _ ->
      Decode.Parser
        (const (Left (Decode.WireTypeError (TL.pack "rendezvous: unknown message type"))))
 where
  requireSub :: Int -> Parser RawMessage RendezvousMessage -> Parser RawMessage RendezvousMessage
  requireSub n p = do
    mParsed <- at (embedded p) (fn n)
    case mParsed of
      Just msg -> pure msg
      Nothing ->
        Decode.Parser
          ( const
              ( Left
                  ( Decode.BinaryError
                      ( TL.pack
                          ("rendezvous: message with type " ++ show n ++ " lacks its submessage")
                      )
                  )
              )
          )

registerParser :: Parser RawMessage RendezvousMessage
registerParser =
  RMRegister
    <$> at (one (TL.toStrict <$> Decode.text) "") (fn 1)
    <*> at (one Decode.byteString BS.empty) (fn 2)
    <*> at (optional Decode.uint64) (fn 3)

registerResponseParser :: Parser RawMessage RendezvousMessage
registerResponseParser =
  ( \status text ttl ->
      RMRegisterResponse (responseStatusFromCode status) text ttl
  )
    <$> at (one Decode.uint64 0) (fn 1)
    <*> at (optional (TL.toStrict <$> Decode.text)) (fn 2)
    <*> at (optional Decode.uint64) (fn 3)

unregisterParser :: Parser RawMessage RendezvousMessage
unregisterParser =
  RMUnregister
    <$> at (one (TL.toStrict <$> Decode.text) "") (fn 1)

discoverParser :: Parser RawMessage RendezvousMessage
discoverParser =
  ( \ns limit cookie ->
      RMDiscover (dropEmptyNs ns) (toLimit limit) cookie
  )
    <$> at (optional (TL.toStrict <$> Decode.text)) (fn 1)
    <*> at (optional Decode.uint64) (fn 2)
    <*> at (one Decode.byteString BS.empty) (fn 3)
 where
  -- An empty ns is "all peers": normalized to Nothing so callers can
  -- distinguish "asked for everything" from a real namespace.
  dropEmptyNs (Just "") = Nothing
  dropEmptyNs ns = ns
  toLimit Nothing = LimitDefault
  toLimit (Just n) = LimitExact n

discoverResponseParser :: Parser RawMessage RendezvousMessage
discoverResponseParser =
  ( \regs cookie status text ->
      RMDiscoverResponse regs cookie (responseStatusFromCode status) text
  )
    <$> at (repeated (embedded' registrationParser)) (fn 1)
    <*> at (one Decode.byteString BS.empty) (fn 2)
    <*> at (one Decode.uint64 0) (fn 3)
    <*> at (optional (TL.toStrict <$> Decode.text)) (fn 4)

registrationParser :: Parser RawMessage RegistrationInfo
registrationParser =
  RegistrationInfo
    <$> at (one (TL.toStrict <$> Decode.text) "") (fn 1)
    <*> at (one Decode.byteString BS.empty) (fn 2)
    <*> at (one Decode.uint64 0) (fn 3)
