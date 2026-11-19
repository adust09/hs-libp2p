-- | Select ordinary failures without swallowing thread cancellation.
module LibP2P.Core.Exception (synchronousException) where

import Control.Exception (SomeAsyncException, SomeException, fromException)

synchronousException :: SomeException -> Maybe SomeException
synchronousException exception =
  case fromException exception :: Maybe SomeAsyncException of
    Just _ -> Nothing
    Nothing -> Just exception
