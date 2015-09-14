{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Network.HMAC.Parse where

import Data.Attoparsec.ByteString
import Data.Attoparsec.ByteString.Char8 (char, decimal, space)
import Data.ByteString (ByteString)
import Network.HMAC.Types

plainTextP :: Parser ByteString
plainTextP = takeWhile1 (inClass "a-zA-Z0-9+/=")
             -- TODO comparing Word8 #s is "faster"

attributeP
    :: forall a.
       ByteString -> Parser a -> Parser a
attributeP key valP =
    skipMany space *>
    string key *> char '=' *> quoteP *> valP <* quoteP
    <* skipMany space
  where
    quoteP = option () (skip isQuote)
    isQuote = (==) 34

idP :: Parser ID
idP = ID <$> (attributeP "id" plainTextP)

tsP :: Parser TS
tsP = TS <$> (attributeP "ts" decimalP)
  where
    decimalP = toInteger <$> decimal

nonceP :: Parser Nonce
nonceP = Nonce <$> (attributeP "nonce" plainTextP)

extP :: Parser Ext
extP = Ext <$> (attributeP "ext" plainTextP)

macP :: Parser Mac
macP = Mac <$> (attributeP "mac" plainTextP)

authP :: Parser Authorization
authP = Authorization <$> idP <*> tsP <*> nonceP <*> maybeExtP <*> macP
  where
    maybeExtP = option Nothing (Just <$> extP)
