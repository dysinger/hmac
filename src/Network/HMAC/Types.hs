{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HMAC.Types where

import Data.ByteString

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
