use std::str::FromStr;

use anyhow::{Error, Result};

pub struct Blake3Hash(pub blake3::Hash);

impl Blake3Hash {
    pub fn to_string(&self) -> String {
        let Self(hash) = self;

        hash.to_string()
    }
}

pub struct BaoHash(pub bao::Hash);

impl BaoHash {
    pub fn to_bytes(&self) -> Vec<u8> {
        let Self(hash) = self;

        hash.as_bytes().to_vec()
    }

    pub fn to_string(&self) -> String {
        let Self(hash) = self;

        hash.to_string()
    }
}

impl TryFrom<&[u8]> for BaoHash {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&value[0..32]);
        Ok(Self(bao::Hash::try_from(hash)?))
    }
}

// impl AsRef<Path> for BaoHash {
//     fn as_ref(&self) -> &Path {
//         let Self(hash) = self;

//         let hash = hash.to_string();

//         Path::new(&hash).as_ref()
//     }
// }

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
