use std::{fs, vec};

use anyhow::Result;
use bao::Hash;
use blake3::hash;
use carbonado::{structs::Encoded, utils::decode_bao_hash};
use carbonado_node::{
    backend::fs::{delete_file, read_catalog, read_file, read_slices, write_file},
    structs::{BaoHash, Blake3Hash, Secp256k1PubKey},
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
    debug!(">>> WRITE FILE REURNS:: hash :: {}", blake3_hash);

    let new_file_bytes = read_file(&Secp256k1PubKey(pk), &blake3_hash).await?;
    debug!(
        ">>> READ FILE REURNS:: bytes read :: {:?}",
        new_file_bytes.len()
    );

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
    debug!("deleted files:: {:?}", new_file_bytes);

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

    let index_start: u64 = 65536;
    let slice_len = 8192;

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("{} Write Delete:: bytes read", file_bytes.len());

    // info!("Write Delete:: Writing file if not exists in order to test delete");
    // write file returns a filehash
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await?;

    // READ FILE CALLs READ CATALOG, IS WHICH DOES THE ENCODING
    let read_file_bytes = read_file(&Secp256k1PubKey(pk), &blake3_hash).await?;
    debug!(">>> FILE LENGTH :: {:?}", &read_file_bytes.len());

    let (encoded_input, hash) = bao::encode::encode(&read_file_bytes);
    debug!(">>> encoded:: {:?}", &encoded_input.len());
    debug!(">>> hash hash:: {:?}", &hash);

    // let bao_hashes = read_file_bytes.chunks_exact(32);
    // debug!(">>> bao_hashes Length:: {:?}", &bao_hashes.len());

    //let mut hash_vec = new Vec();
    // convert u8 32 to blake3 hash
    // let mut hash_vec: Vec<Hash> = Vec::new();
    // let mut hashed: Hash;
    // for hash in bao_hashes {
    //     hashed = decode_bao_hash(hash)?;
    //     let dec_hash = hashed;
    //     hash_vec.push(dec_hash);
    // }

    // debug!(
    //     ">>> decode_bao_hash Hash Vec Length:: {:?}",
    //     &hash_vec.len()
    // );

    let read_the_slice = read_slices(hash, &read_file_bytes, index_start, slice_len)
        .await
        .is_ok();

    //assert!(read_the_slice);

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

//let one = read_file_bytes[1];
// debug!(">>> FILE SLICE:: u8 one:: {:?}", one);
// let five_hundred = read_file_bytes[500];
// debug!(">>> FILE SLICE:: u8  five_hundred:: {:?}", five_hundred);
// let five_thousand = read_file_bytes[5000];
// debug!(">>> FILE SLICE:: u8  five_thousand:: {:?}", five_thousand);
// let fifty_thousand = read_file_bytes[50000];
// debug!(">>> FILE SLICE:: u8  fifty_thousand:: {:?}", fifty_thousand);
// let five_hundred_thousand = read_file_bytes[500000];
// debug!(
//     ">>> FILE SLICE:: u8  five_hundred_thousand:: {:?}",
//     five_hundred_thousand
// );
// let four_mil_five_hundred_thousand = read_file_bytes[4500000];
// debug!(
//     ">>> FILE SLICE:: u8  four_mil_five_hundred_thousand:: {:?}",
//     four_mil_five_hundred_thousand
// );
// let total = read_file_bytes[6170874];
// debug!(">>> FILE SLICE:: u8  6170875:: {:?}", total);
