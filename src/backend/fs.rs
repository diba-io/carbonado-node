use std::{fs::OpenOptions, io::Write, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Result};
use carbonado::{constants::Format, fs::Header, structs::Encoded};
use log::{error, trace};
use once_cell::sync::Lazy;
use rayon::prelude::*;
// use tokio::{
//     fs::OpenOptions,
//     io::AsyncWriteExt,
//     spawn,
//     sync::{
//         watch::{self, Sender},
//         RwLock,
//     },
// };

use crate::{config::SYS_CFG, prelude::*};

pub struct WriteSegment {
    hash: String,
    segment: Arc<[u8]>,
    sk: Arc<[u8]>,
}

// (32-byte Bao hash, 1MB data segment)
// pub static PAR_WRITE: Lazy<RwLock<Option<Sender<Option<WriteSegment>>>>> =
//     Lazy::new(|| RwLock::new(None));

pub async fn write_file(pk: Secp256k1PubKey, file_bytes: &[u8]) -> Result<Blake3Hash> {
    // Segment files
    let segments_iter = file_bytes.par_chunks_exact(1024 * 1024);
    let pk = pk.to_bytes();

    // Encode each segment
    let remainder_bytes = segments_iter.remainder();
    let last_segment = carbonado::encode(&pk, remainder_bytes, NODE_FORMAT)?;

    let mut encoded_segments = segments_iter
        .map(|segment| carbonado::encode(&pk, segment, NODE_FORMAT))
        .collect::<Result<Vec<Encoded>>>()?;

    encoded_segments.push(last_segment);

    // Split each segment out into 8 separate chunks and write each chunk to the storage volume by filename
    encoded_segments.par_iter().for_each(|encoded_segment| {
        let Encoded(encoded_bytes, bao_hash, encode_info) = encoded_segment;

        encoded_bytes
            .par_chunks_exact(encode_info.chunk_len as usize)
            .enumerate()
            .for_each(|(chunk_index, encoded_segment_chunk)| {
                write_segment(
                    sk,
                    path,
                    bao_hash.as_bytes(),
                    NODE_FORMAT,
                    encoded_segment_chunk,
                    chunk_index,
                    encode_info.output_len,
                    encode_info.padding_len,
                );
            });
    });

    // Append each hash to its catalog, plus its format
    todo!("Catalog format");
}

pub async fn read_file(blake3_hash: Blake3Hash) -> Result<Vec<u8>> {
    todo!("TODO: Read file");

    // Read catalog file bytes, parse out each hash, plus the segment Carbonado format

    // For each hash, read each chunk into a segment, then decode that segment

    // Append decoded segment to response vec
}

pub fn write_segment(
    sk: &[u8],
    path: PathBuf,
    hash: &[u8; 32],
    format: u8,
    segment: &[u8],
    chunk_index: usize,
    encoded_len: u32,
    padding_len: u32,
) -> Result<String> {
    let format = Format::try_from(format)?;
    let header = Header::new(
        sk,
        hash,
        format,
        chunk_index as u8,
        encoded_len,
        padding_len,
    )?;
    let header_bytes = header.try_to_vec()?;

    let mut file_path = PathBuf::from(path);
    file_path.push(header.file_name());

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&file_path)?;

    file.write_all(&header_bytes);
    file.write_all(segment);

    Ok(file_path
        .to_str()
        .expect("Turn file path into string")
        .to_string())
}

// pub async fn init_par_writers() -> Result<()> {
//     let (tx, mut rx) = watch::channel(None);

//     *PAR_WRITE.write().await = Some(tx);

//     let sys_cfg_lock = SYS_CFG.read().await;

//     let sys_cfg = sys_cfg_lock
//         .as_ref()
//         .ok_or_else(|| anyhow!("Error getting sys cfg"))?;

//     for (chunk_index, volume) in sys_cfg.volumes.iter().enumerate() {
//         let path = volume.path.to_owned();
//         let rx = rx.clone();
//         spawn(async move {
//             while rx.changed().await.is_ok() {
//                 let write_segment = rx.borrow();

//                 if let Some(write_segment) = write_segment {}

//                 match write_file(path, hash, segment.as_slice(), chunk_index).await {
//                     Ok(msg) => {
//                         trace!("Wrote file: {msg}");
//                     }
//                     Err(err) => {
//                         error!("Error writing file: {err}")
//                     }
//                 }
//             }
//         });
//     }

//     Ok(())
// }
