use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, Write},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, Error, Result};
use axum::body::Bytes;
use carbonado::{constants::Format, file::Header, structs::Encoded};
use futures_util::{stream, Stream, StreamExt, TryStreamExt};
use log::{debug, trace};
use par_stream::{ParStreamExt, TryParStreamExt};
use rayon::{
    prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};
use secp256k1::{PublicKey, SecretKey};
use tokio::sync::Mutex;

use crate::{
    config::{node_shared_secret, SYS_CFG},
    prelude::*,
};

pub type FileStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

pub async fn write_file<'a>(pk: &Secp256k1PubKey, file_stream: FileStream) -> Result<Blake3Hash> {
    trace!("write_file, create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);

    let pk_bytes = write_pk.serialize();
    let (x_only_pk, _) = write_pk.x_only_public_key();

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
    let path = SYS_CFG
        .volumes
        .get(0)
        .expect("First volume present")
        .path
        .join(CATALOG_DIR)
        .join(file_hash.to_string());

    trace!("Check catalog at {path:?}");

    if path.exists() {
        return Err(anyhow!("This file already exists for this public key."));
    }

    trace!("Append each hash to its catalog");
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

            trace!("Open catalog file at {path:?}");
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

pub fn read_file(pk: &Secp256k1PubKey, blake3_hash: &Blake3Hash) -> Result<FileStream> {
    debug!("Read file by hash: {}", blake3_hash.to_string());

    trace!("Read catalog file bytes, parse out each hash, plus the segment Carbonado format");
    let catalog_file = read_catalog(blake3_hash)?;

    trace!("Create a shared secret using ECDH");
    let ss = node_shared_secret(&pk.into_inner())?.secret_bytes();

    trace!("For each hash, read each chunk into a segment, then decode that segment");
    trace!("Segment files");
    let file_bytes: FileStream = stream::iter(catalog_file)
        .par_then(None, move |segment_hash| async move {
            let chunk_path = SYS_CFG
                .volumes
                .get(0)
                .expect("Get first volume")
                .path
                .join(SEGMENT_DIR)
                .join(format!("{segment_hash}.c{NODE_FORMAT}"));

            let mut chunk_file = OpenOptions::new().read(true).open(chunk_path)?;
            let header = Header::try_from(&chunk_file)?;

            let segment: Vec<u8> = if SYS_CFG.drive_redundancy > 1 {
                SYS_CFG
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
                    .collect()
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
        })
        .boxed();

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

pub async fn read_slices(
    //hash: bao::Hash, // from Blake3
    file_bytes: &[u8],
    //slice_start: u64, //let slice_start = 65536;
    //slice_len: u16,   // let slice_len = 8192;
) -> Result<Vec<u8>> {
    use std::io::prelude::*;

    // Start by encoding some input.
    let (encoded_input, hash) = bao::encode::encode(file_bytes);
    debug!(">>> encoded INPUT LENGTH:: {:?}", &encoded_input.len());
    debug!(">>> fs hash hash:: {:?}", &hash);

    // Slice the encoding. These parameters are multiples of the chunk size, which avoids
    // unnecessary overhead.
    let slice_start = 65536;
    let slice_len = 8192;
    let encoded_cursor = std::io::Cursor::new(&encoded_input);
    let mut extractor = bao::encode::SliceExtractor::new(encoded_cursor, slice_start, slice_len);
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;

    // Decode the slice. The result should be the same as the part of the input that the slice
    // represents. Note that we're using the same hash that encoding produced, which is
    // independent of the slice parameters. That's the whole point; if we just wanted to re-encode
    // a portion of the input and wind up with a different hash, we wouldn't need slicing.
    let mut decoded = Vec::new();
    let mut decoder = bao::decode::SliceDecoder::new(&*slice, &hash, slice_start, slice_len);
    decoder.read_to_end(&mut decoded)?;

    debug!(
        "usize vs length: {:?}",
        &encoded_input[slice_start as usize..][..slice_len as usize].len()
    );

    // Like regular decoding, slice decoding will fail if the hash doesn't match.
    // let mut bad_slice = slice.clone();
    // debug!("BAD SLICE");
    // let last_index = bad_slice.len() - 1;
    // bad_slice[last_index] ^= 1;
    // let mut decoder = bao::decode::SliceDecoder::new(&*bad_slice, &hash, slice_start, slice_len);
    // let err = decoder.read_to_end(&mut Vec::new()).unwrap_err();
    // assert_eq!(std::io::ErrorKind::InvalidData, err.kind());

    Ok(decoded)
}

pub async fn delete_file(hash: &String) -> Result<()> {
    let blake3_hash = &Blake3Hash(blake3::Hash::from_str(hash)?);

    for vol in &SYS_CFG.volumes {
        let cat_path = &vol.path.join(CATALOG_DIR).join(hash);
        let test_cat = read_catalog(blake3_hash)?;
        for cat in test_cat {
            let seg_file = &vol.path.join(SEGMENT_DIR).join(cat.to_string() + ".c15");
            let is_removed = fs::remove_file(seg_file).is_ok();
            trace!("{:?} REMOVED:  {:?}", &seg_file, is_removed);
        }

        let is_removed = fs::remove_file(cat_path).is_ok();
        trace!("{:?} REMOVED: {:?}", &cat_path, is_removed);
    }
    Ok(())
}
