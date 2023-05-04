use std::fs;

use anyhow::Result;
use axum::body::Bytes;
use carbonado_node::{backend::fs::write_file, structs::Secp256k1PubKey};
use futures_util::{stream, StreamExt};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::generate_keypair;

const RUST_LOG: &str = "carbonado_node=trace,carbonado=trace,file=trace";

#[tokio::test]
async fn write_read() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    info!("Write Delete:: Writing file if not exists in order to test delete");

    let file_stream = stream::iter(file_bytes)
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    let blake3_hash = write_file(&Secp256k1PubKey(pk), file_stream).await.is_ok();

    if blake3_hash {
        info!(
            "Write File in order to Test Delete File as blake3_hash:: {} ",
            blake3_hash.to_string()
        );
    }

    // TODO: This is not how you delete files
    // let new_file_bytes = delete_file(Secp256k1PubKey(pk), &file_bytes).is_err();
    // debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    debug!(" >>>> Public Key Generated :: {:?} :: {}", _sk, pk);
    info!("Write/Delete test finished successfully!");

    Ok(())
}

#[tokio::test]
async fn check_catalog_exists() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} bytes read", file_bytes.len());

    let file_stream = stream::iter(file_bytes)
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    info!("Writing file if not exists");
    let is_ok = write_file(&Secp256k1PubKey(pk), file_stream).await.is_ok();
    debug!("Skip writing file as File hash exists: {is_ok}");
    assert!(is_ok);

    let file_bytes = fs::read("tests/samples/cat.gif")?;
    let file_stream = stream::iter(file_bytes)
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    info!("Writing file if not exists");
    let is_err = write_file(&Secp256k1PubKey(pk), file_stream).await.is_err();
    debug!("Skip writing file as File hash exists: {is_err}");
    assert!(is_err);

    Ok(())
}

#[tokio::test]
async fn read_write_delete_file() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    let file_stream = stream::iter(file_bytes.clone())
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    // first file to write
    let (_sk, pk) = generate_keypair(&mut thread_rng());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    let file_did_write = write_file(&Secp256k1PubKey(pk), file_stream).await.is_ok();

    if file_did_write {
        info!(
            "Write File Group One to Delete File as blake3_hash:: {} ",
            file_did_write.to_string()
        );
    }

    // second file to write
    let (_sk, pk) = generate_keypair(&mut thread_rng());

    let file_stream = stream::iter(file_bytes)
        .chunks(1024 * 1024)
        .map(|chunk| Ok(Bytes::from(chunk)))
        .boxed();

    info!("Write Delete:: Writing file if not exists in order to test delete");
    let blake3_hash = write_file(&Secp256k1PubKey(pk), file_stream).await.is_ok();

    if blake3_hash {
        info!(
            "Write File in Group Two to Delete File as blake3_hash:: {} ",
            blake3_hash.to_string()
        );
    }

    // TODO: This is not how you delete files
    // let new_file_bytes = delete_file(Secp256k1PubKey(pk), &file_bytes).is_err();
    // debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    // TODO: Check number of files

    debug!(" >>>> Public Key Generated :: {:?} :: {}", _sk, pk);
    info!("Write/Delete test finished successfully!");

    Ok(())
}
