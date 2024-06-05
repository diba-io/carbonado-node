use file_format::FileFormat;
use std::fs;
use tokio::sync::watch;

use anyhow::Result;
use axum::body::Bytes;
use bytes::BytesMut;
use carbonado::structs::Secp256k1PubKey;
use carbonado_node::{
    backend::fs::{read_file, write_file, FileStream},
    config::node_shared_secret,
    prelude::SEGMENT_SIZE,
    structs::{BaoHasher, FileName, Hash, Lookup},
};

use futures_util::{stream, StreamExt, TryStreamExt};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::{generate_keypair, PublicKey, SecretKey};

const RUST_LOG: &str = "carbonado_node=trace,carbonado=trace,file=trace";

#[tokio::test]
async fn write_read() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

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

    let _ = mime_type_sender.send(stage_mime_type.clone());

    info!("Writing file");

    let bao_hasher = BaoHasher::new();
    bao_hasher.update(&file_bytes);
    let orig_hash = bao_hasher.finalize();

    let file_stream: FileStream = stream::iter(file_bytes)
        .chunks(SEGMENT_SIZE)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    let bao_hash = write_file(
        &Secp256k1PubKey::new(pk),
        file_stream,
        FileName::Hashed,
        mime_type_receiver,
    )
    .await?;

    info!("Reading file, {}", bao_hash);

    let decoded_file: Vec<u8> = read_file(
        &Secp256k1PubKey::new(pk),
        &Lookup::Hash(Hash::Bao(bao_hash.clone())),
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
        orig_hash.to_string(),
        bao_hash.to_string(),
        "Original bao hash and streamed hash match",
    );

    // TODO: This is not how you delete files
    // let new_file_bytes = delete_file(Secp256k1PubKey(write_pk), &file_bytes).is_err();
    // debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    info!("Write-read test finished successfully!");

    Ok(())
}
