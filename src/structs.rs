use std::fmt::{self, Display};

use carbonado::utils::BaoHash;
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
