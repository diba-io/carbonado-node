use file_format::FileFormat;
use std::fs;
use tokio::sync::watch;

use anyhow::{Result, anyhow};
use axum::body::Bytes;
use bytes::BytesMut;
use carbonado::file::Header;
use carbonado_node::{
    backend::fs::{FileStream, read_catalog, read_file, write_file},
    config::{file_path, node_shared_secret},
    prelude::{NODE_FORMAT, SEGMENT_DIR, SEGMENT_SIZE},
    structs::{FileName, Hash, Lookup, Secp256k1PubKey},
};

use futures_util::{StreamExt, TryStreamExt, stream};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::{PublicKey, SecretKey, generate_keypair};

#[tokio::test]
async fn write_read() -> Result<()> {
    let (mime_type_sender, mime_type_receiver) = watch::channel("init_mime_type".to_string());

    let (_sk, pk) = generate_keypair(&mut thread_rng());
    // TODO: Use after remove_file is finished:
    // let pk =
    // PublicKey::from_str("032a1c42e4b520d48e7d2661f9af97f8ae646e13a3c0d87f8328da05807a48642d")?;
    let ss = node_shared_secret(&pk)?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    debug!("Public keys - supplied pk: {pk}, write pk: {write_pk}");

    info!("Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    let file_len = file_bytes.len();
    debug!("{} Write Delete:: bytes read", file_len);

    let format = FileFormat::from_bytes(&file_bytes);
    let stage_mime_type = format.media_type().to_string();

    //let mime_type = stage_mime_type;
    let _ = mime_type_sender.send(stage_mime_type.clone());

    info!("Writing file");

    let (x_only, _) = write_pk.x_only_public_key();
    let orig_hash = blake3::keyed_hash(&x_only.serialize(), &file_bytes);

    let file_stream: FileStream = stream::iter(file_bytes)
        .chunks(SEGMENT_SIZE)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    let blake3_hash = write_file(
        &Secp256k1PubKey::new(pk),
        file_stream,
        FileName::PubKeyed,
        mime_type_receiver,
    )
    .await?;

    // Product already encodes Carbonado v2 (encode_with_nonce + Header::new).
    // Assert-only precision: one on-disk segment parses as a v2 Header.
    // Do not use header.pubkey (that field is gone in 0.7).
    let write_pk_str = write_pk.to_string();
    let catalog = read_catalog(
        &write_pk_str,
        &Lookup::Hash(Hash::Blake3(blake3_hash.clone())),
    )?;
    let segment_hash = catalog
        .first()
        .ok_or_else(|| anyhow!("write_file produced no catalog segments"))?;
    let segment_path = file_path(
        0,
        &write_pk_str,
        SEGMENT_DIR,
        &format!("{segment_hash}.c{NODE_FORMAT}"),
    )?;
    let encoded = fs::read(&segment_path)?;
    assert!(
        encoded.len() >= Header::LEN,
        "encoded segment length {} is shorter than Carbonado v2 Header::LEN {}",
        encoded.len(),
        Header::LEN
    );
    let _header = Header::try_from(&encoded[..Header::LEN])?;

    info!("Reading file, {}", blake3_hash);

    let decoded_file: Vec<u8> = read_file(
        &Secp256k1PubKey::new(pk),
        &Lookup::Hash(Hash::Blake3(blake3_hash.clone())),
    )?
    .try_fold(BytesMut::new(), |mut acc, chunk| async move {
        acc.extend(chunk);
        Ok(acc)
    })
    .await?
    .to_vec();

    assert_eq!(
        decoded_file.len(),
        file_len,
        "Decoded file is same size as original"
    );

    assert_eq!(
        orig_hash.to_hex().to_string(),
        blake3_hash.to_string(),
        "Original keyed blake3 hash and streamed hash match",
    );

    // TODO: This is not how you delete files
    // let new_file_bytes = delete_file(Secp256k1PubKey(write_pk), &file_bytes).is_err();
    // debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    info!("Write-read test finished successfully!");

    Ok(())
}

#[tokio::test]
async fn read_write_delete_file() -> Result<()> {
    let (mime_type_sender, mime_type_receiver) = watch::channel("init_mime_type".to_string());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    let format = FileFormat::from_bytes(&file_bytes);
    let stage_mime_type = format.media_type().to_string();

    //let mime_type = stage_mime_type;
    let _ = mime_type_sender.send(stage_mime_type.clone());

    let file_stream = stream::iter(file_bytes.clone())
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    // first file to write
    let (_sk, pk) = generate_keypair(&mut thread_rng());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    let file_did_write = write_file(
        &Secp256k1PubKey::new(pk),
        file_stream,
        FileName::PubKeyed,
        mime_type_receiver.clone(),
    )
    .await
    .is_ok();

    if file_did_write {
        info!("Write File Group One to Delete File as blake3_hash:: {file_did_write} ");
    }

    // second file to write
    let (_sk, pk) = generate_keypair(&mut thread_rng());

    let file_stream = stream::iter(file_bytes)
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    info!("Write Delete:: Writing file if not exists in order to test delete");
    let blake3_hash = write_file(
        &Secp256k1PubKey::new(pk),
        file_stream,
        FileName::PubKeyed,
        mime_type_receiver,
    )
    .await
    .is_ok();

    if blake3_hash {
        info!("Write File in Group Two to Delete File as blake3_hash:: {blake3_hash} ");
    }

    // TODO: This is not how you delete files
    // let new_file_bytes = delete_file(Secp256k1PubKey(pk), &file_bytes).is_err();
    // debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    // TODO: Check number of files

    debug!(" >>>> Public Key Generated :: {:?} :: {}", _sk, pk);
    info!("Write/Delete test finished successfully!");

    Ok(())
}
