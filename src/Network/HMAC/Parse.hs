{-# LANGUAGE OverloadedStrings #-}

module Network.HMAC.Parse where

import           Data.Attoparsec.ByteString.Char8
import qualified Data.Attoparsec.ByteString.Char8 as A
import           Network.HMAC.Types

plainText = inClass "a-zA-Z0-9+/="

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
