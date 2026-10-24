module Main (main) where

import Control.Monad (when)
import Distribution.PackageDescription (
  BuildInfo (extraLibs),
  Library (libBuildInfo),
  PackageDescription (library),
 )
import Distribution.Simple (
  buildHook,
  defaultMainWithHooks,
  preConf,
  simpleUserHooks,
 )
import Distribution.Simple.LocalBuildInfo (buildDir)
import Distribution.Simple.Setup (ConfigFlags (configConfigurationsFlags))
import Distribution.Types.Flag (lookupFlagAssignment, mkFlagName)
import System.Directory (copyFile, createDirectoryIfMissing, makeAbsolute)
import System.Environment (lookupEnv, setEnv)
import System.FilePath (searchPathSeparator, (</>))
import System.Process (callProcess)

main :: IO ()
main =
  defaultMainWithHooks
    simpleUserHooks
      { preConf = \arguments flags -> do
          when (webrtcRequested flags) $ do
            buildWebRTC
            addWebRTCLibraryPath
          preConf simpleUserHooks arguments flags
      , buildHook = \packageDescription localBuildInfo hooks flags -> do
          when (webrtcEnabled packageDescription) $ do
            addWebRTCLibraryPath
            installWebRTCArchive (buildDir localBuildInfo)
          buildHook simpleUserHooks packageDescription localBuildInfo hooks flags
      }

webrtcRequested :: ConfigFlags -> Bool
webrtcRequested flags =
  lookupFlagAssignment (mkFlagName "webrtc") (configConfigurationsFlags flags)
    == Just True

webrtcEnabled :: PackageDescription -> Bool
webrtcEnabled packageDescription =
  maybe False (elem "hs_webrtc" . extraLibs . libBuildInfo) (library packageDescription)

buildWebRTC :: IO ()
buildWebRTC =
  callProcess
    "cargo"
    [ "build"
    , "--release"
    , "--locked"
    , "--manifest-path"
    , "ffi/webrtc/Cargo.toml"
    ]

addWebRTCLibraryPath :: IO ()
addWebRTCLibraryPath = do
  directory <- makeAbsolute "ffi/webrtc/target/release"
  existing <- lookupEnv "LIBRARY_PATH"
  let value = maybe directory (\path -> directory <> [searchPathSeparator] <> path) existing
  setEnv "LIBRARY_PATH" value

installWebRTCArchive :: FilePath -> IO ()
installWebRTCArchive destination = do
  createDirectoryIfMissing True destination
  copyFile
    "ffi/webrtc/target/release/libhs_webrtc.a"
    (destination </> "libhs_webrtc.a")
