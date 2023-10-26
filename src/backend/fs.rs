use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use anyhow::{anyhow, Error, Result};
use axum::{body::Bytes, extract::BodyStream};
use bytes::BytesMut;
use carbonado::{constants::Format, file::Header, structs::Encoded};
use chrono::{NaiveDateTime, TimeZone, Utc};
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
    header::CatHeader,
    prelude::*,
};

pub type FileStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

pub async fn write_file<'a>(
    pk: &Secp256k1PubKey,
    file_stream: FileStream,
    name: Option<String>,
) -> Result<Blake3Hash> {
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

    //let is_mime_type = Arc::new(Mutex::new("mim_type_is?"));

    trace!("Iterate through file body stream");
    let thread_file_hasher = file_hasher.clone();

    // let is_mime_type = is_mime_type.clone();

    let segment_hashes: Vec<(BaoHash, String)> = file_stream
    .try_par_then(None, move |result| {
        async move {
            let segment = match result {
                Ok(Some((segment_bytes, (_, _, mime_type)))) => {
                    // Assuming `segment_bytes` is of type `bytes::Bytes`, and you have a way to calculate `BaoHash`
                    //let hash = calculate_bao_hash(&segment_bytes);
                    let hash = &segment_bytes
                    .iter()
                    .map(|(bao_hash, _)| bao_hash)
                    .collect::<Vec<&BaoHash>>()[..];

                    (hash, mime_type)
                }
                _ => {
                    // If there's an error or no segment, you should handle this case accordingly.
                    // For now, I'll use placeholder values.
                    (BaoHash::default(), "application/octet-stream".to_string())
                }
            }

            trace!("Process segment");
            let thread_file_hasher = thread_file_hasher.clone();

            thread_file_hasher.lock().await.update(&segment.0); // Use segment.0 here since segment is a tuple

            trace!("Encoding segment");
            let encoded_segment = carbonado::encode(&pk_bytes, &segment.0, NODE_FORMAT)?;
            trace!("Writing segment");
            let segment_hash = write_segment(&ss, &pk_bytes, &encoded_segment)?;
            trace!("Segment hash: {segment_hash}");

            // Extract the mime_type from the result here
            let mime_type = segment.1; // Access the mime_type from the tuple

            Ok::<(BaoHash, (_, _, String)), Error>((segment_hash, mime_type))
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
    write_catalog(&write_pk_str, &file_hash, name, "mime_type", seg_hashes).await?;

    debug!("Finished write_file");
    Ok(file_hash)
}

pub fn write_segment(sk: &[u8], pk: &[u8], encoded: &Encoded) -> Result<BaoHash> {
    let Encoded(encoded_bytes, bao_hash, encode_info) = encoded;
    trace!("Encoded bytes len: {}", encoded_bytes.len());

    let encoded_chunk_size = encode_info.bytes_verifiable as usize / SYS_CFG.volumes.len();
    trace!("Encoded chunk size: {}", encoded_chunk_size);

    let metadata = std::option::Option::Some([0_u8; 8]);

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
                metadata,
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
    name: Option<String>,
    mime_type: &str,
    segment_hashes: &[BaoHash],
) -> Result<()> {
    debug!("Write catalog");
    let contents: Vec<u8> = segment_hashes
        .iter()
        .flat_map(|bao_hash| bao_hash.to_bytes())
        .collect();

    let write_pk_str = write_pk_str.to_owned();
    let file_hash = file_hash.to_string();
    let name = name.unwrap_or(file_hash);

    let date_utc = Utc.from_utc_datetime(&NaiveDateTime::from_timestamp_opt(61, 0).unwrap());
    let date = date_utc.to_string();
    let mime_type = mime_type.to_string();

    // HEADER METADATA
    let cat_data = CborData {
        name: name.to_string(),
        date,
        mime_type,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&cat_data)?;
    debug!("cbor data; {:?}", cbor_data);
    // Important, cbor_data.length is used to adjust hash for write_read
    let length = cbor_data.len();
    debug!("cbor lenth:::  {:?}", length);

    stream::iter(0..SYS_CFG.volumes.len())
        .par_map(None, move |volume_index| {
            let write_pk_str = write_pk_str.clone();

            let contents = contents.clone();
            let name = name.clone();
            let cbor_len = length as u8;
            let cbor_data = cbor_data.clone();
            let metadata = Some(cbor_data.clone());

            // convert to <Option[u8; 8]>
            let my_array_option: Option<[u8; 8]> = metadata.and_then(vec_to_array);
            let metadata = my_array_option;

            move || {
                let cat_header = CatHeader { cbor_len, metadata };
                let _cat_header_bytes = cat_header.try_to_vec()?;

                trace!("Get catalogs directory path");
                let path = file_path(volume_index, &write_pk_str, CATALOG_DIR, &name)?;

                // MAKE THE ENDPOINT AVAILABLE
                trace!(">>>> ENDPOINTS <<<<<");
                debug!("Open catalog file at {path:?}");
                // JSON FORMATTED CBOR DATA ENDPOINT
                let decoded_cbor_data: CborData = serde_cbor::from_slice(&cbor_data)?;
                debug!(">>> JSON DATA decoded_cbpr_data; {:?}", decoded_cbor_data);

                trace!("Open catalog file at {path:?}");
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)?;

                // WARNING; adding header to the file, breaks the test.
                // No longer matches origonal hash
                trace!("Write file header, should be added");
                //file.write_all(&cat_header_bytes)?;

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

pub fn read_file(pk: &Secp256k1PubKey, lookup: &Lookup) -> Result<FileStream> {
    debug!("Read file from CATALOG by lookup: {lookup}");

    trace!("Create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();

    trace!("Read catalog file bytes, parse out each hash, plus the segment Carbonado format");
    let catalog_file = read_catalog(&write_pk_str, lookup)?;

    trace!("For each hash, read each chunk into a segment, then decode that segment");
    let file_bytes: FileStream = stream::iter(catalog_file)
        .par_then(None, move |segment_hash| {
            let write_pk_str = write_pk_str.clone();

            async move {
                let chunk_path = file_path(
                    0,
                    &write_pk_str,
                    SEGMENT_DIR,
                    &format!("{}.c{}", segment_hash, NODE_FORMAT),
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
                                let path = file_path(
                                    volume_index,
                                    &write_pk_str,
                                    SEGMENT_DIR,
                                    &format!("{}.c{}", segment_hash, NODE_FORMAT),
                                )?;

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

pub fn read_catalog(write_pk_str: &str, lookup: &Lookup) -> Result<Vec<BaoHash>> {
    let path = file_path(0, write_pk_str, CATALOG_DIR, &lookup.to_string())?;

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

#[allow(unused_variables)]
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

#[allow(unused_variables)]
fn remove_dir_contents<P: AsRef<Path>>(path: P, seg_file: PathBuf) -> io::Result<()> {
    trace!(">>> remove_Segment_contents");
    for entry in fs::read_dir(path)? {
        trace!("Delete Segment File at {:?}", entry);
        fs::remove_file(entry?.path())?;
    }
    Ok(())
}

#[allow(unused_variables)]
fn remove_dir_catalogs(path: PathBuf, file: PathBuf) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        trace!("Delete CATALOG File at {:?}", entry);
        fs::remove_file(entry?.path())?;
    }
    Ok(())
}

fn vec_to_array(vec: Vec<u8>) -> Option<[u8; 8]> {
    if vec.len() == 8 {
        let mut array = [0u8; 8];
        array.copy_from_slice(&vec);
        Some(array)
    } else {
        None
    }
}
