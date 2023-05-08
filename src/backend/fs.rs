use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, Write},
    pin::Pin,
    sync::Arc,
};

use anyhow::{anyhow, Error, Result};
use axum::body::Bytes;
use bytes::BytesMut;
use carbonado::{constants::Format, file::Header, structs::Encoded};
use futures_util::{stream, Stream, StreamExt, TryStreamExt};
use log::{debug, trace};
use par_stream::{ParStreamExt, TryParStreamExt};
use rayon::{
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use secp256k1::{PublicKey, SecretKey};
use tokio::sync::Mutex;

use crate::{
    config::{ensure_pk_dirs_exist, file_path, node_shared_secret, SYS_CFG},
    prelude::*,
};

pub type FileStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

pub async fn write_file<'a>(pk: &Secp256k1PubKey, file_stream: FileStream) -> Result<Blake3Hash> {
    trace!("write_file, create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();

    let pk_bytes = write_pk.serialize();
    let (x_only_pk, _) = write_pk.x_only_public_key();

    ensure_pk_dirs_exist(&write_pk_str).await?;

    trace!("Initialize Blake3 keyed hasher");
    let file_hasher = Arc::new(Mutex::new(blake3::Hasher::new_keyed(
        &x_only_pk.serialize(),
    )));

    trace!("Iterate through file body stream");
    let thread_file_hasher = file_hasher.clone();

    let segment_hashes: Vec<BaoHash> = file_stream
        .try_par_then(None, move |segment: Bytes| {
            trace!("Process segment");
            let thread_file_hasher = thread_file_hasher.clone();
            async move {
                thread_file_hasher.lock().await.update(&segment);
                trace!("Encoding segment");
                let encoded_segment = carbonado::encode(&pk_bytes, &segment, NODE_FORMAT)?;
                trace!("Writing segment");
                let segment_hash = write_segment(&ss, &pk_bytes, &encoded_segment)?;
                trace!("Segment hash: {segment_hash}");

                Ok::<BaoHash, Error>(segment_hash)
            }
        })
        .try_collect()
        .await?;

    let file_hash: Blake3Hash = Blake3Hash(file_hasher.lock().await.finalize());

    trace!("Check if catalog already exists");
    let path = file_path(0, &write_pk_str, CATALOG_DIR, &file_hash.to_string())?;

    trace!("Check catalog at {path:?}");

    if path.exists() {
        return Err(anyhow!("This file already exists for this public key."));
    }

    trace!("Append each hash to its catalog");
    write_catalog(&write_pk_str, &file_hash, &segment_hashes).await?;

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

            let path = file_path(chunk_index, &hex::encode(pk), SEGMENT_DIR, &file_name)?;

            trace!("Write segment at {path:?}");
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

pub async fn write_catalog(
    write_pk_str: &str,
    file_hash: &Blake3Hash,
    segment_hashes: &[BaoHash],
) -> Result<()> {
    debug!("Write catalog");

    let contents: Vec<u8> = segment_hashes
        .iter()
        .flat_map(|bao_hash| bao_hash.to_bytes())
        .collect();

    let write_pk_str = write_pk_str.to_owned();
    let file_hash = file_hash.to_string();

    stream::iter(0..SYS_CFG.volumes.len())
        .par_map(None, move |volume_index| {
            let write_pk_str = write_pk_str.clone();
            let file_hash = file_hash.clone();
            let contents = contents.clone();
            move || {
                trace!("Get catalogs directory path");
                let path = file_path(volume_index, &write_pk_str, CATALOG_DIR, &file_hash)?;

                trace!("Open catalog file at {path:?}");
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)?;

                trace!("Write file contents");
                file.write_all(&contents)?;
                file.flush()?;

                Ok::<(), Error>(())
            }
        })
        .try_collect()
        .await?;

    debug!("Finished write_catalog");
    Ok(())
}

pub fn read_file(pk: &Secp256k1PubKey, blake3_hash: &Blake3Hash) -> Result<FileStream> {
    debug!("Read file by hash: {}", blake3_hash.to_string());

    trace!("Create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();

    trace!("Read catalog file bytes, parse out each hash, plus the segment Carbonado format");
    let catalog_file = read_catalog(&write_pk_str, blake3_hash)?;

    trace!("For each hash, read each chunk into a segment, then decode that segment");
    let file_bytes: FileStream = stream::iter(catalog_file)
        .par_then(None, move |segment_hash| {
            let write_pk_str = write_pk_str.clone();

            async move {
                let chunk_path = file_path(
                    0,
                    &write_pk_str,
                    SEGMENT_DIR,
                    &format!("{segment_hash}.c{NODE_FORMAT}"),
                )?;

                let mut chunk_file = OpenOptions::new().read(true).open(chunk_path)?;
                let header = Header::try_from(&chunk_file)?;

                let segment: Vec<u8> = if SYS_CFG.drive_redundancy > 1 {
                    let segment_hash = segment_hash.to_string();

                    let segment: BytesMut = stream::iter(0..SYS_CFG.volumes.len())
                        .par_map(None, move |volume_index| {
                            let write_pk_str = write_pk_str.clone();
                            let segment_hash = segment_hash.clone();
                            move || {
                                trace!("Get catalogs directory path");
                                let path = file_path(
                                    volume_index,
                                    &write_pk_str,
                                    SEGMENT_DIR,
                                    &segment_hash,
                                )?;

                                trace!("Read segment file at {path:?}");
                                let mut file = OpenOptions::new().read(true).open(path)?;

                                let mut bytes = vec![];
                                file.read_to_end(&mut bytes)?;

                                let (_header, chunk) = bytes.split_at(Header::len());

                                Ok(Bytes::from(chunk.to_vec()))
                            }
                        })
                        .collect::<Vec<Result<Bytes>>>()
                        .await
                        .into_iter()
                        .try_fold(
                            BytesMut::with_capacity(SEGMENT_SIZE * 2),
                            |mut acc, chunk| -> Result<BytesMut, Error> {
                                acc.extend(chunk?);
                                Ok(acc)
                            },
                        )?;

                    segment.to_vec()
                } else {
                    let mut bytes = vec![];
                    chunk_file.rewind()?;
                    chunk_file.read_to_end(&mut bytes)?;
                    let (_header, chunk) = bytes.split_at(Header::len());
                    chunk.to_vec()
                };

                let bytes = carbonado::decode(
                    &ss,
                    &segment_hash.to_bytes(),
                    &segment,
                    header.padding_len,
                    NODE_FORMAT,
                )?;

                Ok(Bytes::from(bytes))
            }
        })
        .boxed();

    debug!("Finish read_file");
    Ok(file_bytes)
}

pub fn read_catalog(write_pk_str: &str, file_hash: &Blake3Hash) -> Result<Vec<BaoHash>> {
    let path = file_path(0, write_pk_str, CATALOG_DIR, &file_hash.to_string())?;

    trace!("Read catalog at {path:?}");
    let mut file = OpenOptions::new().read(true).open(path)?;

    let mut bytes = vec![];
    file.read_to_end(&mut bytes)?;

    let bao_hashes = bytes
        .chunks_exact(bao::HASH_SIZE)
        .map(BaoHash::try_from)
        .collect::<Result<Vec<BaoHash>>>()?;

    Ok(bao_hashes)
}

pub fn read_slice(
    pk: &Secp256k1PubKey,
    file_hash: &Blake3Hash,
    slice_start: usize,
    slice_len: usize,
) -> Result<Vec<BaoHash>> {
    trace!("Create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();

    let path = file_path(0, &write_pk_str, CATALOG_DIR, &file_hash.to_string())?;

    trace!("Read catalog at {path:?}");
    let mut catalog_file = OpenOptions::new().read(true).open(path)?;

    let mut bytes = vec![];
    catalog_file.read_to_end(&mut bytes)?;

    trace!("Read catalog at {:?}", catalog_file);
    trace!(" )))) Read catalog BYTES len()  {:?}", bytes.len());

    // GET RANGE ex: &bytes[1..4]);
    let slice_end = slice_start + slice_len;
    trace!(" {:?}", &bytes[slice_start..slice_end]);

    let bao_hashes = bytes
        .chunks_exact(bao::HASH_SIZE)
        .map(BaoHash::try_from)
        .collect::<Result<Vec<BaoHash>>>()?;

    Ok(bytes)
}

pub async fn delete_file(pk: &Secp256k1PubKey) -> Result<()> {
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();
    trace!("WRITE_PK_STR: {}", write_pk_str);

    for vol in &SYS_CFG.volumes {
        trace!("VOLUME PATH: {:?}", vol.path);

        let pk_path = vol.path.join(&write_pk_str);
        let is_removed = fs::remove_dir_all(pk_path).is_ok();
        trace!(
            "VOLUME_{:?} WRITE_PK_STR REMOVED {:?}: ",
            vol.path,
            is_removed
        );
    }
    Ok(())
}
