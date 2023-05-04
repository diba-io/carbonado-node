#![allow(unused_variables)]

use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Error, Result};
use axum::body::Bytes;
use carbonado::{constants::Format, file::Header, structs::Encoded};
use futures_util::{stream::BoxStream, StreamExt, TryStreamExt};
use log::{debug, trace};
use rayon::prelude::*;
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};

use crate::{config::SYS_CFG, prelude::*};

pub type FileStream<'a> = BoxStream<'a, Result<Bytes>>;

pub async fn write_file<'a>(
    pk: &Secp256k1PubKey,
    file_stream: FileStream<'a>,
) -> Result<Blake3Hash> {
    trace!("write_file, create a shared secret using ECDH");
    let sk = SYS_CFG.private_key;
    let ss = SharedSecret::new(&pk.into_inner(), &sk).secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);

    let pk_bytes = write_pk.serialize();
    let (x_only_pk, _) = write_pk.x_only_public_key();

    trace!("Initialize Blake3 keyed hasher");
    let mut file_hasher = blake3::Hasher::new_keyed(&x_only_pk.serialize());

    trace!("Iterate through file body stream");
    let segment_hashes = file_stream
        .map(|segment: Result<Bytes>| {
            let segment = segment?;
            file_hasher.update(&segment);
            let encoded_segment = carbonado::encode(&pk_bytes, &segment, NODE_FORMAT)?;
            let segment_hash = write_segment(&ss, &pk_bytes, &encoded_segment)?;

            Ok::<BaoHash, Error>(segment_hash)
        })
        .try_collect::<Vec<BaoHash>>()
        .await?;

    let file_hash: Blake3Hash = Blake3Hash(file_hasher.finalize());

    trace!("Check if segment already exists");
    let path = SYS_CFG
        .volumes
        .get(0)
        .expect("First volume present")
        .path
        .join(CATALOG_DIR)
        .join(file_hash.to_string());

    trace!("Read catalog at {path:?}");

    if path.exists() {
        return Err(anyhow!("This file already exists for this public key."));
    }

    trace!("Append each hash to its catalog, plus its format");
    write_catalog(&file_hash, &segment_hashes)?;

    debug!("Finished write_file");
    Ok(file_hash)
}

pub fn write_segment(sk: &[u8], pk: &[u8], encoded: &Encoded) -> Result<BaoHash> {
    let Encoded(encoded_bytes, bao_hash, encode_info) = encoded;
    trace!("Encoded bytes len: {}", encoded_bytes.len());

    let encoded_chunk_size = encode_info.bytes_verifiable as usize / SYS_CFG.volumes.len();
    trace!("Encoded chunk size: {}", encoded_chunk_size);

    encoded_bytes
        .par_chunks_exact(encoded_chunk_size)
        .enumerate()
        .map(|(chunk_index, encoded_segment_chunk)| {
            let volume = SYS_CFG
                .volumes
                .get(chunk_index)
                .expect("Get one of eight volumes");

            let format = Format::try_from(NODE_FORMAT)?;
            let header = Header::new(
                sk,
                pk,
                bao_hash.as_bytes(),
                format,
                chunk_index as u8,
                encode_info.output_len,
                encode_info.padding_len,
            )?;
            let header_bytes = header.try_to_vec()?;
            let file_name = header.file_name();

            let volume = SYS_CFG
                .volumes
                .get(chunk_index)
                .expect("Get one of eight volumes");

            let path = volume.path.join(SEGMENT_DIR).join(file_name);

            trace!("Write segment at {}", path.to_string_lossy());
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;

            file.write_all(&header_bytes)?;
            file.write_all(encoded_segment_chunk)?;
            file.flush()?;

            Ok(())
        })
        .collect::<Result<Vec<()>>>()?;

    Ok(BaoHash(bao_hash.to_owned()))
}

pub fn write_catalog(file_hash: &Blake3Hash, segment_hashes: &[BaoHash]) -> Result<()> {
    debug!("Write catalog");
    let contents: Vec<u8> = segment_hashes
        .iter()
        .flat_map(|bao_hash| bao_hash.to_bytes())
        .collect();

    SYS_CFG
        .volumes
        .par_iter()
        .map(|volume| {
            trace!("Get catalogs directory path");
            let path = volume.path.join(CATALOG_DIR).join(file_hash.to_string());

            trace!("Open catalog file at {}", path.to_string_lossy());
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;

            trace!("Write file contents");
            file.write_all(&contents)?;
            file.flush()?;

            Ok(())
        })
        .collect::<Result<()>>()?;

    debug!("Finished write_catalog");
    Ok(())
}

pub async fn read_file(pk: &Secp256k1PubKey, blake3_hash: &Blake3Hash) -> Result<Vec<u8>> {
    debug!("Read file by hash: {}", blake3_hash.to_string());

    trace!("Read catalog file bytes, parse out each hash, plus the segment Carbonado format");
    let catalog_file = read_catalog(blake3_hash)?;

    trace!("Create a shared secret using ECDH");
    let sk = SYS_CFG.private_key;
    let ss = SharedSecret::new(&pk.into_inner(), &sk);
    let ss_bytes = ss.secret_bytes();

    trace!("For each hash, read each chunk into a segment, then decode that segment");
    trace!("Segment files");
    let file_bytes = catalog_file
        .par_iter()
        .flat_map(|segment_hash| {
            let chunk_path = SYS_CFG
                .volumes
                .get(0)
                .expect("Get first volume")
                .path
                .join(SEGMENT_DIR)
                .join(format!("{segment_hash}.c{NODE_FORMAT}"));

            let chunk_file = OpenOptions::new().read(true).open(chunk_path).unwrap();
            let header = Header::try_from(chunk_file).unwrap();

            let segment = SYS_CFG
                .volumes
                .par_iter()
                .flat_map(|volume| {
                    let path = volume
                        .path
                        .join(SEGMENT_DIR)
                        .join(format!("{segment_hash}.c{NODE_FORMAT}"));

                    let mut file = OpenOptions::new().read(true).open(path).unwrap();

                    let mut bytes = vec![];
                    file.read_to_end(&mut bytes).unwrap();

                    let (_header, chunk) = bytes.split_at(Header::len());

                    chunk.to_owned()
                })
                .collect::<Vec<u8>>();

            carbonado::decode(
                &ss_bytes,
                &segment_hash.to_bytes(),
                &segment,
                header.padding_len,
                NODE_FORMAT,
            )
            .unwrap()
        })
        .collect::<Vec<u8>>();

    debug!("Finish read_file");
    Ok(file_bytes)
}

pub fn read_catalog(file_hash: &Blake3Hash) -> Result<Vec<BaoHash>> {
    let path = SYS_CFG
        .volumes
        .get(0)
        .expect("First volume present")
        .path
        .join(CATALOG_DIR)
        .join(file_hash.to_string());

    trace!("Read catalog at {}", path.to_string_lossy());
    let mut file = OpenOptions::new().read(true).open(path)?;

    let mut bytes = vec![];
    file.read_to_end(&mut bytes)?;

    let bao_hashes = bytes
        .chunks_exact(bao::HASH_SIZE)
        .map(BaoHash::try_from)
        .collect::<Result<Vec<BaoHash>>>()?;

    Ok(bao_hashes)
}

pub fn delete_file(pk: Secp256k1PubKey, file_bytes: &[u8]) -> Result<()> {
    let pk_bytes = pk.to_bytes();
    let (x_only_pk, _) = pk.into_inner().x_only_public_key();

    let file_hash = Blake3Hash(blake3::keyed_hash(&x_only_pk.serialize(), file_bytes));
    trace!(">>>>>file_hash::   {}", file_hash);

    for vol in &SYS_CFG.volumes {
        let seg_file = &vol.path.join(SEGMENT_DIR).join(file_hash.to_string());
        let seg_dir = &vol.path.join(SEGMENT_DIR);
        remove_dir_contents(seg_dir, seg_file.to_path_buf()).unwrap();
    }

    for vol in &SYS_CFG.volumes {
        let cat_path = &vol.path.join(CATALOG_DIR).join(file_hash.to_string());
        let cat = &vol.path.join(CATALOG_DIR);
        remove_dir_catalogs(cat.to_path_buf(), cat_path.to_path_buf()).unwrap();
    }
    Ok(())
}

fn remove_dir_contents<P: AsRef<Path>>(path: P, seg_file: PathBuf) -> io::Result<()> {
    trace!(">>> remove_Segment_contents");
    for entry in fs::read_dir(path)? {
        trace!("Delete Segment File at {:?}", entry);
        fs::remove_file(entry?.path())?;
    }
    Ok(())
}

fn remove_dir_catalogs(path: PathBuf, file: PathBuf) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        trace!("Delete CATALOG File at {:?}", entry);
        fs::remove_file(entry?.path())?;
    }
    Ok(())
}

// fn remove_dir_segements<P: AsRef<Path>>(path: P, seg_file: PathBuf) -> io::Result<()> {
//     trace!(">>> remove_Segment_contents");
//     for entry in fs::read_dir(path)? {
//         let entry = entry?;
//         trace!("ENTRY Delete SEGMENT File at {:?}", entry);

//         match &entry {
//             seg_file => {
//                 fs::remove_file(seg_file.path())?;
//                 trace!("Delete Segment File at {:?}", seg_file);
//             }
//         }
//     }
//     Ok(())
// }

// fn remove_dir_catalogs(path: PathBuf, file: PathBuf) -> io::Result<()> {
//     for entry in fs::read_dir(path)? {
//         let entry = entry?;
//         trace!("ENTRY Delete CATALOG File at {:?}", entry);
//         match &entry {
//             file => {
//                 fs::remove_file(file.path())?;
//                 trace!("FILE MATCH Delete CATALOG File at {:?}", file);
//             }
//         }
//     }
//     Ok(())
// }
