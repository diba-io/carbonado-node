#![allow(unused_variables)]

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use carbonado::{constants::Format, fs::Header, structs::Encoded};
// use log::{error, trace};
use rayon::prelude::*;
use secp256k1::ecdh::SharedSecret;

use crate::{
    config::{ENV_CFG, SYS_CFG},
    prelude::*,
};

pub async fn write_file(pk: Secp256k1PubKey, file_bytes: &[u8]) -> Result<Blake3Hash> {
    // Hash file
    let pk_bytes = pk.to_bytes();
    let (x_only_pk, _) = pk.into_inner().x_only_public_key();

    let file_hash = Blake3Hash(blake3::keyed_hash(&x_only_pk.serialize(), file_bytes));

    // Check if file catalog already exists

    // Segment files
    let segments_iter = file_bytes.par_chunks_exact(SEGMENT_SIZE);

    // Encode each segment
    let remainder_bytes = segments_iter.remainder();
    let last_segment = carbonado::encode(&pk_bytes, remainder_bytes, NODE_FORMAT)?;

    let mut encoded_segments = segments_iter
        .map(|segment| carbonado::encode(&pk_bytes, segment, NODE_FORMAT))
        .collect::<Result<Vec<Encoded>>>()?;

    encoded_segments.push(last_segment);

    // Get eight storage volumes from config
    let cfg = SYS_CFG.read().await.clone();

    let cfg = match &*cfg {
        Some(cfg) => cfg,
        None => return Err(anyhow!("No config")),
    };

    if cfg.volumes.len() != 8 {
        return Err(anyhow!("Eight volume paths must be configured"));
    }

    // Create a shared secret using ECDH
    let sk = cfg.private_key;
    let ss = SharedSecret::new(&pk.into_inner(), &sk);

    // Split each segment out into 8 separate chunks and write each chunk to the storage volume by filename
    let segment_hashes = encoded_segments
        .par_iter()
        .map(|encoded_segment| {
            let Encoded(encoded_bytes, bao_hash, encode_info) = encoded_segment;

            encoded_bytes
                .par_chunks_exact(encode_info.chunk_len as usize)
                .enumerate()
                .map(|(chunk_index, encoded_segment_chunk)| {
                    let volume = cfg
                        .volumes
                        .get(chunk_index)
                        .expect("Get one of eight volumes");

                    write_segment(
                        &ss.secret_bytes(),
                        volume.path.clone(),
                        bao_hash.as_bytes(),
                        NODE_FORMAT,
                        encoded_segment_chunk,
                        chunk_index,
                        encode_info.output_len,
                        encode_info.padding_len,
                    )
                })
                .collect::<Result<Vec<()>>>()?;

            Ok(BaoHash(bao_hash.to_owned()))
        })
        .collect::<Result<Vec<BaoHash>>>()?;

    // Append each hash to its catalog, plus its format
    write_catalog(&file_hash, &segment_hashes)?;

    Ok(file_hash)
}

pub async fn read_file(blake3_hash: &Blake3Hash) -> Result<Vec<u8>> {
    // Read catalog file bytes, parse out each hash, plus the segment Carbonado format
    let catalog_file = read_catalog(blake3_hash)?;

    // Get eight storage volumes from config
    let cfg = SYS_CFG.read().await.clone();

    let cfg = match &*cfg {
        Some(cfg) => cfg,
        None => return Err(anyhow!("No config")),
    };

    if cfg.volumes.len() != 8 {
        return Err(anyhow!("Eight volume paths must be configured"));
    }

    // For each hash, read each chunk into a segment, then decode that segment
    // Segment files
    let file_bytes = catalog_file
        .par_iter()
        .flat_map(|segment_hash| {
            let path = cfg
                .volumes
                .get(0)
                .expect("Get first volume")
                .path
                .join(segment_hash.to_string());
            let file = OpenOptions::new().read(true).open(path).unwrap();
            let header = carbonado::fs::Header::try_from(file).unwrap();

            // Create a shared secret using ECDH
            let sk = cfg.private_key;
            let ss = SharedSecret::new(&header.pubkey, &sk);

            let segment = cfg
                .volumes
                .par_iter()
                .flat_map(|volume| {
                    let path = volume.path.join(segment_hash.to_string());

                    let mut file = OpenOptions::new().read(true).open(path).unwrap();

                    let mut bytes = vec![];
                    file.read_to_end(&mut bytes).unwrap();

                    let (_header, chunk) = bytes.split_at(carbonado::fs::header_len() as usize);

                    chunk.to_owned()
                })
                .collect::<Vec<u8>>();

            carbonado::decode(
                &ss.secret_bytes(),
                &segment_hash.to_bytes(),
                &segment,
                header.padding_len,
                NODE_FORMAT,
            )
            .unwrap()
        })
        .collect::<Vec<u8>>();

    Ok(file_bytes)
}

#[allow(clippy::too_many_arguments)]
pub fn write_segment(
    sk: &[u8],
    path: PathBuf,
    hash: &[u8; 32],
    format: u8,
    segment: &[u8],
    chunk_index: usize,
    encoded_len: u32,
    padding_len: u32,
) -> Result<()> {
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

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path.join(header.file_name()))?;

    file.write_all(&header_bytes)?;
    file.write_all(segment)?;

    Ok(())
}

pub fn write_catalog(file_hash: &Blake3Hash, segment_hashes: &[BaoHash]) -> Result<PathBuf> {
    let contents: Vec<u8> = segment_hashes
        .iter()
        .flat_map(|bao_hash| bao_hash.to_bytes())
        .collect();

    let path = ENV_CFG
        .data_cfg_dir
        .join("catalogs")
        .join(file_hash.to_string());

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;

    file.write_all(&contents)?;

    Ok(path)
}

pub fn read_catalog(file_hash: &Blake3Hash) -> Result<Vec<BaoHash>> {
    let mut file = OpenOptions::new().read(true).open(file_hash.to_string())?;

    let mut bytes = vec![];
    file.read_to_end(&mut bytes)?;

    let bao_hashes = bytes
        .chunks_exact(bao::HASH_SIZE)
        .map(BaoHash::try_from)
        .collect::<Result<Vec<BaoHash>>>()?;

    Ok(bao_hashes)
}
