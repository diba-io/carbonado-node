use std::{
    fmt::{self, Display},
    io::{Cursor, Write},
    sync::{Arc, RwLock},
};

use anyhow::{Error, Result};
use bao::encode::Encoder;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Blake3Hash(pub blake3::Hash);

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Self(hash) = self;

        f.write_str(&hash.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct BaoHash(pub bao::Hash);

impl BaoHash {
    pub fn to_bytes(&self) -> Vec<u8> {
        let Self(hash) = self;

        hash.as_bytes().to_vec()
    }
}

impl fmt::Display for BaoHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Self(hash) = self;

        f.write_str(&hash.to_string())
    }
}

impl TryFrom<&[u8]> for BaoHash {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&value[0..32]);
        Ok(Self(bao::Hash::from(hash)))
    }
}

// impl AsRef<Path> for BaoHash {
//     fn as_ref(&self) -> &Path {
//         let Self(hash) = self;

//         let hash = hash.to_string();

//         Path::new(&hash).as_ref()
//     }
// }

#[derive(Clone, Debug)]
pub enum Hash {
    Blake3Bytes(Box<[u8]>),
    BaoBytes(Box<[u8]>),
    Blake3(Blake3Hash),
    Bao(BaoHash),
}

#[derive(Clone, Debug)]
pub enum Lookup {
    Hash(Hash),
    Name(String),
}

impl Display for Lookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lookup::Hash(hash) => match hash {
                Hash::Blake3Bytes(_) => todo!(),
                Hash::BaoBytes(_) => todo!(),
                Hash::Blake3(blake3_hash) => f.write_str(&blake3_hash.to_string()),
                Hash::Bao(hash) => f.write_str(&hash.to_string()),
            },
            Lookup::Name(name) => f.write_str(name),
        }
    }
}

pub enum PubKey {
    Secp256k1Bytes(Box<[u8]>),
    Secp256k1(secp256k1::PublicKey),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]

pub struct CborData {
    /// Number of bytes added to pad to align zfec chunks and bao slices.
    pub name: String,
    pub date: String,
    pub mime_type: String,
    // pub metadata: Option<Vec<u8>>,
}

pub enum FileName {
    Named(String),
    PubKeyed,
    Hashed,
    // None,
}

pub struct BaoHasher {
    encoder: Arc<RwLock<Encoder<Cursor<Vec<u8>>>>>,
}

impl BaoHasher {
    pub fn new() -> Arc<Self> {
        let data = Vec::new();
        let cursor = Cursor::new(data.clone());
        let encoder = Encoder::new(cursor);

        let bao_hasher = Self {
            encoder: Arc::new(RwLock::new(encoder)),
        };

        Arc::new(bao_hasher)
    }

    pub fn update(&self, buf: &[u8]) {
        let mut encoder = self.encoder.write().expect("encoder write lock");
        encoder.write_all(buf).expect("write to encoder");
    }

    pub fn finalize(&self) -> BaoHash {
        let mut encoder = self.encoder.write().expect("encoder read lock");

        BaoHash(encoder.finalize().expect("finalize bao hash"))
    }

    pub fn read_all(&self) -> Vec<u8> {
        let encoder = self.encoder.write().expect("encoder read lock");
        let data = encoder.clone().into_inner();
        data.into_inner().to_vec()
    }
}
