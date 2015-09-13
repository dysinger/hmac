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
    -- , nonce :: Nonce
    -- , ext :: Maybe Ext
    -- , mac :: Mac
    } deriving (Eq,Show)

plainText = inClass "a-zA-Z0-9"

padded x = skipMany space *> x <* skipMany space

idParser :: Parser ID
idParser = ID <$> padded (string "id=" *> takeWhile1 plainText)

tsParser :: Parser TS
tsParser = TS <$> padded (string "ts=" *> (toInteger <$> decimal))

nonceParser :: Parser Nonce
nonceParser = Nonce <$> padded (string "nonce=" *> takeWhile1 plainText)

extParser :: Parser Ext
extParser = Ext <$> padded (string "ext=" *> takeWhile1 plainText)

macParser :: Parser Mac
macParser = Mac <$> padded (string "mac=" *> takeWhile1 plainText)

authParser :: Parser Authorization
authParser = go idParser [tsParser, nonceParser, extParser, macParser]
  go x ys =
  -- try idParser ()
  Authorization <$> idParser <*> tsParser -- <*> nonceParser <*> maybe extParser <*> macParser
