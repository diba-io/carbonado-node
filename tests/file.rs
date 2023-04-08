use std::fs;

use anyhow::Result;
use carbonado::structs::Encoded;
use carbonado_node::{
    backend::fs::{delete_file, read_catalog, read_file, read_slices, write_file},
    structs::{BaoHash, Secp256k1PubKey},
};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::generate_keypair;

const RUST_LOG: &str = "carbonado_node=trace,carbonado=trace,file=trace";

#[tokio::test]
// #[should_panic]
async fn file_read() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    // write file returns a filehash
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await?;

    let new_file_bytes = read_file(&Secp256k1PubKey(pk), &blake3_hash).await?;
    debug!(">>> READ FILE REURNS:: bytes read :: {:?}", new_file_bytes);

    Ok(())
}

#[tokio::test]
// #[should_panic]
async fn check_catalog_exists() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    // write file returns a filehash
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await?;

    info!("Reading file by hash");
    let new_file_bytes = read_catalog(&blake3_hash)?;
    debug!("{} new bytes read", new_file_bytes.len());

    let new_file_bytes = delete_file(Secp256k1PubKey(pk), &file_bytes).is_err();
    debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    debug!(" >>>> Public Key Generated :: {:?} :: {}", _sk, pk);
    info!("Write/Delete test finished successfully!");

    Ok(())
}

// #[tokio::test]
// // #[should_panic]
// async fn check_catalog_exists() -> Result<()> {
//     carbonado::utils::init_logging(RUST_LOG);

//     let (_sk, pk) = generate_keypair(&mut thread_rng());

//     info!("Reading file bytes");
//     let file_bytes = fs::read("tests/samples/cat.gif")?;
//     debug!("{} bytes read", file_bytes.len());

//     info!("Writing file if not exists");
//     let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await.is_err();
//     debug!("Skip writing file as File hash exists: {blake3_hash}");
//     assert!(blake3_hash);

//     Ok(())
// }

#[tokio::test]
// #[should_panic]
async fn get_slice() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let index_start = 65536;
    let slice_len = 8192;

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    // write file returns a filehash
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await?;

    // READ FILE CALL READ CATALOG, IS WHICH DOES THE ENCODING
    let read_file_bytes = read_file(&Secp256k1PubKey(pk), &blake3_hash).await?;
    debug!(
        ">>> READ FILE RETURNS:: bytes read :: {:?}",
        read_file_bytes
    );

    // expected struct `bao::Hash`, found struct `structs::Secp256k1PubKey`
    // how to get a boa hash?
    // let bao_hashes = file_bytes // or bytes ??
    //     .chunks_exact(bao::HASH_SIZE)
    //     .map(BaoHash::try_from)
    //     .collect::<Result<Vec<&bao::Hash>>>()?;

    let Encoded(encoded_bytes, bao_hash, encode_info) = read_file_bytes;

    let read_the_slice = read_slices(bao_hashes, &read_file_bytes, index_start, slice_len)
        .await
        .is_ok();

    assert!(read_the_slice);

    Ok(())
}

#[tokio::test]
async fn read_write_delete_file() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    // first file to write
    let (_sk, pk) = generate_keypair(&mut thread_rng());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    let file_did_write = write_file(&Secp256k1PubKey(pk), &file_bytes).await.is_ok();

    if file_did_write {
        info!(
            "Write File Group One to Delete File as blake3_hash:: {} ",
            file_did_write.to_string()
        );
    }

    // second file to write
    let (_sk, pk) = generate_keypair(&mut thread_rng());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await.is_ok();

    if blake3_hash {
        info!(
            "Write File in Group Two to Delete File as blake3_hash:: {} ",
            blake3_hash.to_string()
        );
    }

    let new_file_bytes = delete_file(Secp256k1PubKey(pk), &file_bytes).is_err();
    debug!("Write Delete:: deleted file:: {:?}", new_file_bytes);

    debug!(" >>>> Public Key Generated :: {:?} :: {}", _sk, pk);
    info!("Write/Delete test finished successfully!");

    Ok(())
}
