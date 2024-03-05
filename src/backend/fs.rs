use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, RwLock},
};

use tokio::sync::watch;

use anyhow::{anyhow, Error, Result};
use bytes::{Bytes, BytesMut};
use carbonado::{
    constants::Format,
    file::Header,
    structs::{Encoded, Secp256k1PubKey},
};
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
    file_name: FileName,
    mime_type_receiver: watch::Receiver<String>,
) -> Result<Blake3Hash> {
    trace!("write_file, create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();
    let pk_bytes = write_pk.serialize();
    let (x_only_pk, _) = write_pk.x_only_public_key();

    ensure_pk_dirs_exist(&write_pk_str).await?;

    trace!("Initialize Blake3 keyed hasher");
    let file_hasher = Arc::new(RwLock::new(match file_name {
        FileName::PubKeyed => blake3::Hasher::new_keyed(&x_only_pk.serialize()),
        _ => blake3::Hasher::new(),
    }));
    let thread_file_hasher = file_hasher.clone();

    trace!("Iterate through file body stream");

    let current_mime_type = Arc::new(Mutex::new(mime_type_receiver.borrow().clone()));
    let mime_type_receiver_clone = mime_type_receiver.clone();
    let current_mime_type_clone = current_mime_type.clone();

    let segment_hashes: Vec<BaoHash> = file_stream
        .map(move |segment: Result<Bytes>| {
            let segment = segment?;
            thread_file_hasher
                .write()
                .expect("write_file write lock")
                .update(&segment);
            Ok(segment)
        })
        .try_par_then(None, move |segment: Bytes| {
            let current_mime_type = Arc::clone(&current_mime_type_clone);
            let mut mime_type_receiver = mime_type_receiver_clone.clone();

            debug!("Process segment");

            async move {
                if mime_type_receiver.changed().await.is_ok() {
                    let new_mime_type = mime_type_receiver.borrow().clone();
                    if new_mime_type != "application/octet-stream" {
                        *current_mime_type.lock().await = new_mime_type;
                    }
                }

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

    let file_hash = Blake3Hash(file_hasher.read().expect("write_file read lock").finalize());

    trace!("Check if catalog already exists");
    let path = file_path(0, &write_pk_str, CATALOG_DIR, &file_hash.to_string())?;

    trace!("Check catalog at {path:?}");

    if path.exists() {
        return Err(anyhow!(
            "This file already exists for this public key. Its hash is: {file_hash}"
        ));
    }

    // Access the updated MIME type after the loop
    let final_mime_type_str = current_mime_type.lock().await.clone();
    debug!(">>>>>>>>>> Mime_Type has Changed {final_mime_type_str:?}");

    let write_pk_str = write_pk_str.to_owned();
    let file_name = match file_name {
        FileName::Named(name) => name,
        FileName::PubKeyed => file_hash.to_string(),
        FileName::Hashed => file_hash.to_string(),
    };

    trace!("Append each hash to its catalog");
    write_catalog(
        write_pk_str,
        file_name,
        &final_mime_type_str,
        &segment_hashes,
    )
    .await?;

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
            let format = Format::from(NODE_FORMAT);
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
    write_pk_str: String,
    file_name: String,
    mime_type: &str,
    segment_hashes: &[BaoHash],
) -> Result<()> {
    debug!("Write catalog");
    let contents: Vec<u8> = segment_hashes
        .iter()
        .flat_map(|bao_hash| bao_hash.to_bytes())
        .collect();

    let date_utc = Utc.from_utc_datetime(&NaiveDateTime::from_timestamp_opt(61, 0).unwrap());
    let date = date_utc.to_string();
    let mime_type = mime_type.to_string();

    debug!("Write catalog  mime_type to meda-data {}", mime_type);

    // HEADER METADATA
    let cat_data = CborData {
        name: file_name.to_string(),
        date,
        mime_type,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&cat_data)?;
    let length = cbor_data.len();

    stream::iter(0..SYS_CFG.volumes.len())
        .par_map(None, move |volume_index| {
            let write_pk_str = write_pk_str.clone();

            let contents = contents.clone();
            let name = file_name.clone();
            let cbor_len = length as u8;
            let cbor_data = cbor_data.clone();
            let metadata = Some(cbor_data.clone());

            // convert to <Option[u8; 8]>
            let my_array_option: Option<[u8; 8]> = metadata.and_then(vec_to_array);
            let metadata = my_array_option;

            move || {
                let cat_header = CatHeader { cbor_len, metadata };
                let cat_header_bytes = cat_header.try_to_vec()?;

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

                file.write_all(&cat_header_bytes)?;

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
    trace!("Create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();

    trace!(
        ">>>>>> Read catalog file bytes, parse out each hash, plus the segment Carbonado format"
    );
    let catalog_file = read_catalog(&write_pk_str, lookup)?;

    let catalog_file_clone = catalog_file.clone();

    trace!("For each hash, read each chunk into a segment, then decode that segment");
    let file_bytes: FileStream = stream::iter(catalog_file_clone)
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

    // Split the CatHeader bytes from the content bytes
    let (_cat_header, content_bytes) = bytes.split_at(25);

    let bao_hashes = content_bytes
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
