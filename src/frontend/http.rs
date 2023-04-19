use anyhow::Result;
use std::borrow::Borrow;
use std::sync::RwLock;
use std::{net::SocketAddr, str::FromStr};
//use axum::extract::FromRequestParts;
use axum::{
    body::Bytes,
    extract::Path,
    extract::Query,
    http::{header::CONTENT_TYPE, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use log::{debug, info};

use serde::Deserialize;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, read_slices, write_file},
    prelude::*,
};

static LOCK: std::sync::RwLock<std::string::String> = RwLock::new(String::new());

//#[derive(Deserialize, std::fmt::Debug)]

// can use Options Here.
// struct File {
//     pk: String,
//     black3_hash: String,
// }

#[derive(Deserialize, std::fmt::Debug)]

// can use Options Here.
struct FileSlice {
    pk: String,
    black3_hash: String,
    index_start: u64,
    range_end: u64,
}

async fn post_file<'a>(Path(pk): Path<String>, body: Bytes) -> Result<impl IntoResponse, AppError> {
    let _pk = &Secp256k1PubKey::try_from(pk.as_str())?;
    let hash = write_file(_pk, &body).await?;
    debug!("#### HTTP WHAT IS FILE HASH {}", hash.borrow());
    let hash_to_string = hash.to_string();
    let mut w = LOCK.write().unwrap();
    *w = hash_to_string;

    Ok((StatusCode::OK, "my_hash"))
}

#[axum_macros::debug_handler]
async fn get_last_hash(Path(_pk): Path<String>) -> Result<impl IntoResponse, AppError> {
    //let _pk = Secp256k1PubKey::try_from(pk.as_str())?;

    let hash1 = LOCK.read().unwrap();
    //debug!("#### RwLock last_HASH {:?}", *hash1);
    let string_hash1 = hash1.clone();

    Ok((StatusCode::OK, string_hash1))
}

#[axum_macros::debug_handler]
async fn get_file(
    Path((pk, blake3_hash)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let pk = Secp256k1PubKey::try_from(pk.as_str())?;
    let blake3_hash = Blake3Hash(blake3::Hash::from_str(&blake3_hash)?);
    let _file_bytes = read_file(&pk, &blake3_hash).await?;
    debug!("#### HTTP TEST WHAT IS FILE my_HASH {:?}", _file_bytes);
    Ok((StatusCode::OK, _file_bytes))
}

async fn get_slice(my_params: Query<FileSlice>) -> Result<impl IntoResponse, AppError> {
    // have to call read_file() to provide the bytes to slice from
    let pk = Secp256k1PubKey::try_from(my_params.pk.as_str())?;
    let blake3_hash = Blake3Hash(blake3::Hash::from_str(&my_params.black3_hash)?);
    let file_bytes = read_file(&pk, &blake3_hash).await?;

    // use the file_bytes to encode input and hash
    let (encoded_input, hash) = bao::encode::encode(&file_bytes);
    debug!(">>> encoded:: {:?}", &encoded_input.len());
    debug!(">>> hash hash:: {:?}", &hash);
    // use the file_butes in call to get_slices

    let read_the_slice = read_slices(
        hash,
        &file_bytes,
        my_params.index_start,
        my_params.range_end as u16,
    )
    .await
    .is_ok();

    debug!(">>> hash hash:: {:?}", &read_the_slice);

    Ok((StatusCode::OK, "read_the_slice"))
}

#[axum_macros::debug_handler]
async fn remove_file(
    Path((pk, blake3_hash)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let pk = Secp256k1PubKey::try_from(pk.as_str())?;
    delete_file(pk, blake3_hash.as_bytes())?;
    Ok((StatusCode::OK, blake3_hash))
}

pub async fn start() -> Result<()> {
    let app = Router::new()
        .route("/remove/:pk/:blake3_hash", delete(remove_file))
        .route("/store/:pk", post(post_file))
        .route("/last_hash/:pk", get(get_last_hash))
        .route("/retrieve/:pk/:blake3_hash", get(get_file))
        .route("/slice/", get(get_slice))
        // .route("/catalog/:blake3_hash", get(get_catalog))
        // .route("/raw/:bao_hash", get(get_raw))
        //.layer(CorsLayer::permissive());
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin("http://localhost:8080".parse::<HeaderValue>().unwrap())
                .allow_headers([CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST, Method::DELETE]),
        );

    let addr = SocketAddr::from(([127, 0, 0, 1], 7000));

    info!("carbonado-node HTTP frontend successfully running at {addr}");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

// https://github.com/tokio-rs/axum/blob/fef95bf37a138cdf94985e17f27fd36481525171/examples/anyhow-error-response/src/main.rs
// Make our own error that wraps `anyhow::Error`.
struct AppError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
