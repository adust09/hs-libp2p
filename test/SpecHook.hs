module SpecHook (hook) where

import System.IO (hSetEncoding, stderr, stdin, stdout, utf8)
import Test.Hspec (Spec, runIO)

hook :: Spec -> Spec
hook nestedSpecs = do
    runIO configureUtf8
    nestedSpecs

configureUtf8 :: IO ()
configureUtf8 = do
    hSetEncoding stdin utf8
    hSetEncoding stdout utf8
    hSetEncoding stderr utf8
