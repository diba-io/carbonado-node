use std::{net::SocketAddr, str::FromStr, sync::RwLock};

use anyhow::Result;
use axum::{
    extract::{BodyStream, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use futures_util::{
    stream::{self},
    StreamExt,
};
use log::{debug, info};
use tower_http::cors::CorsLayer;

use crate::backend::fs::read_slices;
use crate::{
    backend::fs::{delete_file, read_file, write_file, FileStream},
    config::SYS_CFG,
    prelude::*,
};
use serde::Deserialize;

static LOCK: std::sync::RwLock<std::string::String> = RwLock::new(String::new());

#[derive(Deserialize, std::fmt::Debug)]

// can use Options Here.
struct FileSlice {
    pk: String,
    black3_hash: String,
    index_start: u64,
    range_end: u16,
}

#[axum_macros::debug_handler]
async fn post_file(
    Path(pk): Path<String>,
    body: BodyStream,
) -> Result<impl IntoResponse, AppError> {
    let pk = &Secp256k1PubKey::try_from(pk.as_str())?;

    let file_stream: FileStream = stream::try_unfold(body, |mut body_stream| async {
        if let Some(chunk) = body_stream.next().await {
            let bytes = chunk?;
            Ok(Some((bytes, body_stream)))
        } else {
            Ok(None)
        }
    })
    .boxed();

    let Blake3Hash(hash) = write_file(pk, file_stream).await?;

    // store hash into lock to get a response body for carbonado client
    let hash_to_string = hash.to_string();
    let mut w = LOCK.write().unwrap();
    *w = hash_to_string;

    Ok((StatusCode::OK, hash.to_hex().to_string()))
}

#[axum_macros::debug_handler]
async fn get_last_hash(Path(_pk): Path<String>) -> Result<impl IntoResponse, AppError> {
    let hash1 = LOCK.read().unwrap();
    let string_hash1 = hash1.clone();

    Ok((StatusCode::OK, string_hash1))
}

#[axum_macros::debug_handler]
async fn get_file(
    Path((pk, blake3_hash)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let pk = Secp256k1PubKey::try_from(pk.as_str())?;
    let blake3_hash = Blake3Hash(blake3::Hash::from_str(&blake3_hash)?);
    let file_bytes = read_file(&pk, &blake3_hash).await?;

    Ok((StatusCode::OK, file_bytes))
}

#[axum_macros::debug_handler]
async fn get_slice(my_params: Query<FileSlice>) -> Result<impl IntoResponse, AppError> {
    let true_form_key = "0".to_owned() + &my_params.pk;
    let pk = Secp256k1PubKey::try_from(true_form_key.as_str())?;
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
        my_params.range_end,
    )
    .await?;

    Ok((StatusCode::OK, read_the_slice))
}

#[axum_macros::debug_handler]
async fn remove_file(Path(blake3_hash): Path<String>) -> Result<impl IntoResponse, AppError> {
    delete_file(&blake3_hash).await?;
    Ok((StatusCode::OK, blake3_hash))
}

pub async fn start() -> Result<()> {
    let app = Router::new()
        .route("/remove/:blake3_hash", delete(remove_file))
        .route("/store/:pk", post(post_file))
        .route("/last_hash/:pk", get(get_last_hash))
        .route("/retrieve/:pk/:blake3_hash", get(get_file))
        .route("/slice/", get(get_slice))
        // .route("/catalog/:blake3_hash", get(get_catalog))
        // .route("/raw/:bao_hash", get(get_raw))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], SYS_CFG.http_port));

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
