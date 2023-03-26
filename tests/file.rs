use std::{fs, str::FromStr};

use anyhow::Result;
use carbonado_node::{
    backend::fs::{delete_file, read_file, write_file},
    structs::{Blake3Hash, Secp256k1PubKey},
};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::generate_keypair;

const RUST_LOG: &str = "carbonado_node=trace,carbonado=trace,file=trace";

// #[tokio::test]
// async fn write_read() -> Result<()> {
//     carbonado::utils::init_logging(RUST_LOG);

//     let (_sk, pk) = generate_keypair(&mut thread_rng());

//     info!("Reading file bytes");
//     let file_bytes = fs::read("tests/samples/cat.gif")?;
//     debug!("{} bytes read", file_bytes.len());

//     info!("Writing file");
//     let blake3_hash = write_file(Secp256k1PubKey(pk), &file_bytes).await?;
//     debug!("File hash: {blake3_hash}");

//     // info!("Reading file by hash");
//     // let new_file_bytes = read_file(&blake3_hash).await?;
//     // debug!("{} new bytes read", new_file_bytes.len());

//     // assert_eq!(
//     //     file_bytes, new_file_bytes,
//     //     "Written and read file matches bytes"
//     // );

//     // info!("File write/read test finished successfully!");

//     Ok(())
// }

#[tokio::test]
// #[should_panic]
async fn check_catalog_exists() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} bytes read", file_bytes.len());

    info!("Writing file if not exists");
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await.is_err();
    debug!("Skip writing file as File hash exists: {blake3_hash}");
    assert!(blake3_hash);

    Ok(())
}

#[tokio::test]
async fn write_delete_file() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await.is_ok();

    if blake3_hash {
        info!(
            "Write File in order to Delete:: blake3_hash:: {} ",
            blake3_hash.to_string()
        );
    }

    let new_file_bytes = delete_file(Secp256k1PubKey(pk), &file_bytes).is_err();
    debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    debug!(" >>>> Public Key Generated :: {:?} :: {}", _sk, pk);
    info!("Write/Delete test finished successfully!");

    Ok(())
}
