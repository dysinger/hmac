{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HMAC where

import           Control.Applicative ((<|>))
import           Data.Attoparsec.ByteString.Char8
import qualified Data.Attoparsec.ByteString.Char8 as A
import           Data.ByteString
import           Data.Word

data ID =
    ID ByteString
    deriving (Eq,Show)

data TS =
    TS Integer
    deriving (Eq,Show)

data Nonce =
    Nonce ByteString
    deriving (Eq,Show)

data Ext =
    Ext ByteString
    deriving (Eq,Show)

data Mac =
    Mac ByteString
    deriving (Eq,Show)

data Authorization = Authorization
    { id' :: ID
    , ts :: TS
    , nonce :: Nonce
    , ext :: Maybe Ext
    , mac :: Mac
    } deriving (Eq,Show)

plainText = inClass "a-zA-Z0-9"

padded x = skipMany space *> x <* skipMany space

idP :: Parser ID
idP = ID <$> padded (string "id=" *> takeWhile1 plainText)

tsP :: Parser TS
tsP = TS <$> padded (string "ts=" *> (toInteger <$> decimal))

nonceP :: Parser Nonce
nonceP = Nonce <$> padded (string "nonce=" *> takeWhile1 plainText)

extP :: Parser Ext
extP = Ext <$> padded (string "ext=" *> takeWhile1 plainText)

macP :: Parser Mac
macP = Mac <$> padded (string "mac=" *> takeWhile1 plainText)

authP :: Parser Authorization
authP = Authorization <$> idP <*> tsP <*> nonceP <*> maybeExtP <*> macP
  where
    maybeExtP = option Nothing (Just <$> extP)
