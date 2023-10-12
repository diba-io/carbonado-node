use crate::errors::CarbonadoNodeError;
use log::debug;
use serde::{Deserialize, Serialize};
use serde_cbor;
use serde_cbor::Error;

use bytes::Bytes;
use nom::{
    bytes::complete::take,
    number::complete::le_u8, // if cbor length is actually u32
    IResult,
};

use crate::constants::CAT_MAGICNO;

/// Contains deserialized copies of the data kept in the Catalog header.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CatHeader {
    /// Number of bytes added to pad to align zfec chunks and bao slices.
    pub cbor_len: u8, // this appears to sbe u32 not u8
    /// Bytes that are normally zero but can contain extra data if needed
    pub metadata: Option<[u8; 8]>,
}

impl TryFrom<&[u8]> for CatHeader {
    type Error = CarbonadoNodeError;

    /// Attempts to decode a cat_header from a file.
    fn try_from(bytes: &[u8]) -> Result<Self, CarbonadoNodeError> {
        let cat_magic_no = [0_u8; 16];

        // easily get cbor_length back from header to know how far to read
        let (_, (cbor_len, metadata)) = CatHeader::parse_bytes(bytes).unwrap();

        //  create throw error for wrong magic number
        if cat_magic_no != CAT_MAGICNO {
            return Err(CarbonadoNodeError::CatInvalidMagicNumber(format!(
                "{cat_magic_no:#?}"
            )));
        }

        Ok(CatHeader { cbor_len, metadata })
    }
}

impl TryFrom<Bytes> for CatHeader {
    type Error = CarbonadoNodeError;

    /// Attempts to decode a header from a file.
    fn try_from(bytes: Bytes) -> Result<Self, CarbonadoNodeError> {
        let cat_magic_no = [0_u8; 16];

        let (_, (cbor_len, metadata)) = CatHeader::parse_bytes(&bytes).unwrap();

        if cat_magic_no != CAT_MAGICNO {
            return Err(CarbonadoNodeError::CatInvalidMagicNumber(format!(
                "{cat_magic_no:#?}"
            )));
        }

        Ok(CatHeader { cbor_len, metadata })
    }
}

impl CatHeader {
    /// 160 bytes should be added for Carbonado headers.
    pub fn len() -> usize {
        12 + 33 + 32 + 64 + 1 + 1 + 4 + 4 + 8 + 1
    }

    /// Creates a new Catalog Header struct using the provided parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(metadata: [u8; 8]) -> Result<Self, Error> {
        //type Error = CarbonadoError;
        let cbor_data = serde_cbor::to_vec(&metadata)?;
        println!("cbor data; {:?}", cbor_data);

        let cbor_leng = cbor_data.len() as u8;

        // cbor length is header length
        println!("cbor length ; {:?}", cbor_leng);

        Ok(CatHeader {
            cbor_len: cbor_leng,
            metadata: if metadata.iter().any(|b| b != &0) {
                Some(metadata)
            } else {
                None
            },
        })
    }

    /// Creates a header to be prepended to files.
    pub fn try_to_vec(&self) -> Result<Vec<u8>, CarbonadoNodeError> {
        let mut cbor_bytes = self.cbor_len.to_le_bytes().to_vec(); // 2 bytes
        let mut cbor_padding = if let Some(metadata) = &self.metadata {
            // debug!(
            //     ">>> SELF METADATA IF STATEMENT : {:?}",
            //     &metadata.to_vec()
            // );

            metadata.to_vec()
        } else {
            debug!("### ERROR ELSE STATEMENT [0_u8; 8]");
            vec![0_u8; 8]
        };

        debug!(">>>> CBORE BYTES LENGTH : {}", self.cbor_len);

        let mut cat_header = Vec::new();

        cat_header.append(&mut CAT_MAGICNO.to_vec()); // 12 bytes
        cat_header.append(&mut cbor_bytes);
        cat_header.append(&mut cbor_padding);

        // if header.len() != CatHeader::len() {
        //     return Err(CarbonadoError::InvalidHeaderLength);
        // }

        Ok(cat_header)
    }

    #[allow(clippy::type_complexity)]
    fn parse_bytes(b: &[u8]) -> IResult<&[u8], (u8, Option<[u8; 8]>)> {
        let (b, cbor_len) = le_u8(b)?;
        let (b, metadata) = take(8u8)(b)?;

        let metadata: [u8; 8] = metadata.try_into().expect("8 bytes = 8 bytes");
        let metadata = if metadata.iter().any(|b| b != &0) {
            Some(metadata)
        } else {
            None
        };

        Ok((b, (cbor_len, metadata)))
    }
}

pub fn encode_cbor(cat_header: Option<[u8; 8]>) -> Result<(), Error> {
    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&cat_header)?;
    println!("cbor data; {:?}", cbor_data);
    Ok(())
}
