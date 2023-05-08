use std::fs;

use anyhow::Result;
use axum::body::Bytes;
use bytes::BytesMut;
use carbonado_node::{
    backend::fs::{delete_file, read_file, write_file, FileStream},
    config::{node_shared_secret, SYS_CFG},
    prelude::{CATALOG_DIR, SEGMENT_DIR, SEGMENT_SIZE},
    structs::Secp256k1PubKey,
};
use futures_util::{stream, StreamExt, TryStreamExt};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::{generate_keypair, PublicKey, SecretKey};

const RUST_LOG: &str = "carbonado_node=trace,carbonado=trace,file=trace";

#[tokio::test]
async fn write_read() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

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

    info!("Writing file");

    let (x_only, _) = write_pk.x_only_public_key();
    let orig_hash = blake3::keyed_hash(&x_only.serialize(), &file_bytes);

    let file_stream: FileStream = stream::iter(file_bytes)
        .chunks(SEGMENT_SIZE)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    let blake3_hash = write_file(&Secp256k1PubKey(pk), file_stream).await?;

    info!("Reading file");

    let decoded_file: Vec<u8> = read_file(&Secp256k1PubKey(pk), &blake3_hash)?
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
    carbonado::utils::init_logging(RUST_LOG);

    // write file to test delete
    let (_sk, pk) = generate_keypair(&mut thread_rng());

    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    let file_stream = stream::iter(file_bytes)
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    info!("Write Delete:: Writing file if not exists in order to test delete");
    let final_blake3_hash = write_file(&Secp256k1PubKey(pk), file_stream).await?;

    info!(
        "File To Delete as blake3_hash:: {} ",
        final_blake3_hash.to_string()
    );

    let ss = node_shared_secret(&Secp256k1PubKey(pk).into_inner())?.secret_bytes();
    let write_pk = PublicKey::from_secret_key_global(&SecretKey::from_slice(&ss)?);
    let write_pk_str = write_pk.to_string();

    //  Check number of catalog files
    let mut current_volume = -1; // start for volume 0
    for vol in &SYS_CFG.volumes {
        current_volume += 1;
        let seg_file = &vol.path.join(&write_pk_str).join(CATALOG_DIR);

        let paths = fs::read_dir(seg_file).unwrap();
        let mut counter = 0;
        for path in paths {
            counter += 1;
            debug!(
                "Catalog count: {:?} :: path: {}",
                counter,
                path.unwrap().path().display()
            )
        }
        debug!(
            "CATALOGS Volume: {}, total deleted: {:?}",
            current_volume, counter
        );
    }

    // // Check number of segment files
    let mut current_volume = -1; // start for volume 0
    for vol in &SYS_CFG.volumes {
        current_volume += 1;
        let seg_file = &vol.path.join(&write_pk_str).join(SEGMENT_DIR);

        let paths = fs::read_dir(seg_file).unwrap();
        let mut counter = 0;
        for path in paths {
            counter += 1;
            debug!(
                "Segment count: {:?} :: path: {}",
                counter,
                path.unwrap().path().display()
            )
        }
        debug!(
            "SEGMENT Volume: {}, total deleted: {:?}",
            current_volume, counter
        );
    }

    // Delete Files for blake3_hash
    let new_file_bytes = delete_file(&Secp256k1PubKey(pk)).await.is_ok();
    debug!("Deleted files success:: {:?}", new_file_bytes);

    info!("Write/Delete test finished successfully!");

    Ok(())
}
