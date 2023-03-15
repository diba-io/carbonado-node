use std::fs;

use anyhow::Result;
use carbonado_node::{
    backend::fs::{read_file, write_file},
    structs::Secp256k1PubKey,
};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::generate_keypair;

const RUST_LOG: &str = "carbonad_node=trace,carbonado=trace,file=trace";

#[tokio::test]
async fn write_read() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} bytes read", file_bytes.len());

    info!("Writing file");
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await?;
    debug!("File hash: {blake3_hash}");

    info!("Reading file by hash");
    let new_file_bytes = read_file(&Secp256k1PubKey(pk), &blake3_hash).await?;
    debug!("{} new bytes read", new_file_bytes.len());

    assert_eq!(
        file_bytes, new_file_bytes,
        "Written and read file matches bytes"
    );

    info!("File write/read test finished successfully!");

    Ok(())
}
