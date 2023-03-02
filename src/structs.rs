use std::{fmt, str::FromStr};

use anyhow::Error;

pub struct Blake3Hash(pub blake3::Hash);

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Self(hash) = self;

        f.write_str(&hash.to_string())
    }
}

pub struct BaoHash(pub bao::Hash);

impl BaoHash {
    pub fn to_bytes(&self) -> Vec<u8> {
        let Self(hash) = self;

        hash.as_bytes().to_vec()
    }
}

pub enum Hash {
    Blake3Bytes(Box<[u8]>),
    BaoBytes(Box<[u8]>),
    Blake3(Blake3Hash),
    Bao(BaoHash),
}

pub struct Secp256k1PubKey(pub secp256k1::PublicKey);

impl TryFrom<&str> for Secp256k1PubKey {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let pk = secp256k1::PublicKey::from_str(value)?;

        Ok(Self(pk))
    }
}

impl Secp256k1PubKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let Self(pk) = self;

        pk.serialize().to_vec()
    }

    pub fn into_inner(&self) -> secp256k1::PublicKey {
        let Self(pk) = self;

        pk.to_owned()
    }
}

pub enum PubKey {
    Secp256k1Bytes(Box<[u8]>),
    Secp256k1(secp256k1::PublicKey),
}
