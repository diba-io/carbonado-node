use std::str::FromStr;

use anyhow::Error;

pub struct Blake3Hash(pub blake3::Hash);
pub struct BaoHash(pub bao::Hash);

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

impl<'a> Secp256k1PubKey {
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

pub struct Segment {
    hash: Hash,
    index: u32,
}

pub struct Catalog {
    scope: PubKey,
    segments: Vec<Segment>,
}

/// Tasks
pub enum Task {
    WriteFile,
    ReadFile,
    EncodeSegment,
    DecodeSegment,
    EncodeFile,
    DecodeFile(Catalog),
}
