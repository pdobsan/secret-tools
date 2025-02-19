{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.SecretTools
  ( decryptFile,
    encryptFile,
    lookupSecret,
    storeSecret,
    SecretToolsError (..),
  )
where

import System.Directory qualified as D
import System.Exit (ExitCode (ExitSuccess))
import System.IO qualified as IO
import System.Process qualified as P
import Text.Printf (printf)

type KeyID = String

type Secret = String

data SecretToolsError
  = FileError String
  | DecryptError String
  | EncryptError String
  | LookupError String
  | StoreError String
  deriving (Show)

decryptFile :: FilePath -> IO (Either SecretToolsError Secret)
decryptFile f = do
  -- check gpg environment
  fOk <- D.doesFileExist f
  if fOk
    then do
      (x, o, e) <- P.readProcessWithExitCode "gpg" ["--decrypt", f] ""
      if x == ExitSuccess
        then return $ Right o
        else
          pure $ Left $ DecryptError e
    else pure $ Left $ FileError $ printf "Can't open file: %s\n" f

encryptFile :: FilePath -> Secret -> KeyID -> IO (Either SecretToolsError String)
encryptFile f s k = do
  fOk <- D.doesFileExist f
  if fOk
    then do
      (Just h, _, _, p) <-
        P.createProcess
          (P.proc "gpg" ["--encrypt", "--recipient", k, "-o", f ++ ".tmp"])
            { P.std_in = P.CreatePipe
            }
      IO.hPutStr h s
      IO.hFlush h
      IO.hClose h
      x <- P.waitForProcess p
      if x == ExitSuccess
        then do
          D.renameFile (f ++ ".tmp") f
          pure $ Right "gpg encryption succeded."
        else pure $ Left $ EncryptError "gpg encryption failed."
    else pure $ Left $ FileError $ printf "Can't open file: %s\n" f

type Attribute = String

type Value = String

type Label = String

lookupSecret :: Attribute -> Value -> IO (Either SecretToolsError String)
lookupSecret attribute value = do
  (x, o, e) <- P.readProcessWithExitCode "secret-tool" ["lookup", attribute, value] ""
  if x == ExitSuccess
    then return $ Right o
    else pure $ Left $ LookupError e

storeSecret :: Label -> Attribute -> Value -> Secret -> IO (Either SecretToolsError String)
storeSecret label attribute value secret = do
  (Just h, _, _, p) <-
    P.createProcess
      (P.proc "secret-tool" ["store", "--label", label, attribute, value])
        { P.std_in = P.CreatePipe
        }
  IO.hPutStr h secret
  IO.hFlush h
  IO.hClose h
  x <- P.waitForProcess p
  if x == ExitSuccess
    then return $ Right "secret stored."
    else pure $ Left $ StoreError "Storing secret failed."
