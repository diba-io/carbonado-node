use std::{fs, sync::RwLock};

use anyhow::Result;
use axum::body::Bytes;
use carbonado_node::{
    backend::fs::{delete_file, write_file},
    config::SYS_CFG,
    structs::Secp256k1PubKey,
};
use futures_util::{stream, StreamExt};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::generate_keypair;

const RUST_LOG: &str = "carbonado_node=trace,carbonado=trace,file=trace";
static COUNT_CAT: std::sync::RwLock<u8> = RwLock::new(0);
static COUNT_SEG: std::sync::RwLock<u8> = RwLock::new(0);

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

    let blake3_hash = write_file(&Secp256k1PubKey(pk), file_stream).await?;

    info!(
        "Write File in order to Test Delete File as blake3_hash:: {} ",
        blake3_hash.to_string()
    );

    // Clean up files by utilizing delete files
    let new_file_bytes = delete_file(&blake3_hash.to_string()).await.is_ok();
    debug!("Delete:: deleted file:: {:?}", new_file_bytes);

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

    // info!("Write Delete:: Reading file bytes");
    // let file_bytes = fs::read("tests/samples/cat.gif")?;
    // debug!("{} Write Delete:: bytes read", file_bytes.len());

    // let file_stream = stream::iter(file_bytes)
    //     .chunks(1024 * 1024)
    //     .map(|chunk| Ok(Bytes::from(chunk)))
    //     .boxed();

    // // first file to write
    // let (_sk, pk) = generate_keypair(&mut thread_rng());

    // // info!("Write Delete:: Writing file if not exists in order to test delete");
    // let file_did_write = write_file(&Secp256k1PubKey(pk), file_stream).await?;

    // info!(
    //     "DON'T Delete FIRST File as blake3_hash:: {} ",
    //     file_did_write.to_string()
    // );

    // second file to write
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

    // Delete Files for blake3_hash
    let new_file_bytes = delete_file(&final_blake3_hash.to_string()).await.is_ok();
    debug!("Delete:: deleted file:: {:?}", new_file_bytes);

    // Check number of files
    for vol in &SYS_CFG.volumes {
        let cat_file = &vol.path.join("/tmp/carbonado-0/catalogs");
        let paths = fs::read_dir(cat_file).unwrap();
        for path in paths {
            let mut w = COUNT_CAT.write().unwrap();
            *w += 1;
            debug!(
                "Catalog count: {:?} :: path: {}",
                w,
                path.unwrap().path().display()
            )
        }
    }
    let final_count = COUNT_CAT.read().unwrap();
    debug!("Total CATALOG Files: {:?}", final_count);

    info!("Write/Delete test finished successfully!");

    // Check number of files
    for vol in &SYS_CFG.volumes {
        let seg_file = &vol.path.join("/tmp/carbonado-0/segments");
        let paths = fs::read_dir(seg_file).unwrap();
        for path in paths {
            let mut w = COUNT_SEG.write().unwrap();
            *w += 1;
            debug!(
                "Segment count: {:?} :: path: {}",
                w,
                path.unwrap().path().display()
            )
        }
    }
    let final_count = COUNT_SEG.read().unwrap();
    debug!("Total SEGMENT Files: {:?}", final_count);

    info!("Write/Delete test finished successfully!");

    Ok(())
}
