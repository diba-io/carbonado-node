use carbonado::error::CarbonadoError;
use log::debug;
use serde::{Deserialize, Serialize};
use serde_cbor;
use serde_cbor::Error;

use crate::constants::MAGICNO;

// use crate::{
//     constants::{Format, MAGICNO},
//     error::CarbonadoError,
// };

/// Contains deserialized copies of the data kept in the Catalog header.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CatHeader {
    /// Number of bytes added to pad to align zfec chunks and bao slices.
    pub cbor_len: u8,
    /// Bytes that are normally zero but can contain extra data if needed
    pub metadata: Option<Vec<u8>>,
}

impl CatHeader {
    /// 160 bytes should be added for Carbonado headers.
    pub fn len() -> usize {
        12 + 33 + 32 + 64 + 1 + 1 + 4 + 4 + 8 + 1
    }

    /// Creates a new Catalog Header struct using the provided parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(metadata: Vec<u8>) -> Result<Self, Error> {
        //type Error = CarbonadoError;
        let cbor_data = serde_cbor::to_vec(&metadata)?;
        println!("cbor data; {:?}", cbor_data);

        let cbor_len = cbor_data.len() as u8;

        println!("cbor length ; {:?}", cbor_len);

        Ok(CatHeader {
            cbor_len,
            metadata: if metadata.iter().any(|b| b != &0) {
                Some(metadata)
            } else {
                None
            },
        })
    }

    /// Creates a header to be prepended to files.
    pub fn try_to_vec(&self) -> Result<Vec<u8>, CarbonadoError> {
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

        let mut header = Vec::new();

        header.append(&mut MAGICNO.to_vec()); // 12 bytes
        header.append(&mut cbor_bytes);
        header.append(&mut cbor_padding);

        // if header.len() != CatHeader::len() {
        //     return Err(CarbonadoError::InvalidHeaderLength);
        // }

        Ok(header)
    }
}

pub fn encode_cbor(cat_header: Option<[u8; 8]>) -> Result<(), Error> {
    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&cat_header)?;
    println!("cbor data; {:?}", cbor_data);
    Ok(())
}
