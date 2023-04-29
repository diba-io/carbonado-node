use anyhow::{anyhow, Ok, Result};
use carbonado_node::{
    backend::fs::{delete_file, read_catalog, read_file, read_slices, write_file},
    structs::Secp256k1PubKey,
};
use log::{debug, info};
use rand::thread_rng;
use secp256k1::generate_keypair;
use std::fs;

const RUST_LOG: &str = "carbonado_node=trace,carbonado=trace,file=trace";

// #[tokio::test]
// async fn catalog_file_exists_dont_write() -> Result<()> {
//     carbonado::utils::init_logging(RUST_LOG);

//     //let (_sk, pk) = generate_keypair(&mut thread_rng());
//     let pk = "035daafa302424d1bd492a38b280225bb3cc6db1082220d581d5d24fb2e2e71ebc";
//     let _pk = &Secp256k1PubKey::try_from(pk)?;

//     info!("Don't Write:: Reading file bytes");
//     let file_bytes = fs::read("tests/samples/cat.gif")?;
//     debug!("Don't Write :: bytes read {}", file_bytes.len());

//     // write file returns a filehash
//     // let blake3_hash = write_file(_pk, &file_bytes).await?;
//     // debug!(">>> WRITE FILE ONCE:: hash :: {}", blake3_hash);

//     // write file returns a filehash
//     let blake3_hash = write_file(_pk, &file_bytes).await.is_err();
//     debug!(">>> WRITE FILE TWICE TO ERROR:: hash :: {}", blake3_hash);
//     if blake3_hash {
//         return Ok(debug!("File didn't write as it exists"));
//     } else {
//         // this is a negative test
//         return Err(anyhow!("This file already exists for this user."));
//     }

//     Ok(())
// }

#[tokio::test]
async fn file_read() -> Result<()> {
    carbonado::utils::init_logging(RUST_LOG);

    let (_sk, pk) = generate_keypair(&mut thread_rng());

    info!("Write Delete:: Reading file bytes");
    let file_bytes = fs::read("tests/samples/cat.gif")?;
    debug!("FILE READ :: bytes read {}", file_bytes.len());

    // write file returns a filehash
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await?;
    debug!(">>> WRITE FILE RETURNS:: hash :: {}", blake3_hash);

    let new_file_bytes = read_file(&Secp256k1PubKey(pk), &blake3_hash).await?;
    debug!(
        ">>> READ FILE RETURNS:: bytes read :: {:?}",
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
    let blake3_hash = write_file(&Secp256k1PubKey(pk), &file_bytes).await?;

    // READ FILE CALLs READ CATALOG
    let read_file_bytes = read_file(&Secp256k1PubKey(pk), &blake3_hash).await?;
    debug!(">>> FILE LENGTH :: {:?}", &read_file_bytes.len());

    let (encoded_input, hash) = bao::encode::encode(&read_file_bytes);
    debug!(">>> encoded:: {:?}", &encoded_input.len());
    debug!(">>> hash:: {:?}", &hash);

    let read_slice = read_slices(hash, &read_file_bytes, index_start, slice_len).await?;

    debug!(">>> decode_bao_hash Hash Vec Length:: {:?}", read_slice);

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
    debug!("Ddeleted file:: {:?}", new_file_bytes);
    info!("Write/Delete test finished successfully!");

    Ok(())
}
