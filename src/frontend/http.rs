use std::{net::SocketAddr, str::FromStr};

use anyhow::Result;
//use axum::extract::FromRequestParts;
use axum::{
    body::Bytes,
    extract::Path,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use log::{debug, info};

use serde::Deserialize;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, write_file},
    prelude::*,
};

#[derive(Deserialize, std::fmt::Debug)]

// can use Options Here.
struct FileSlice {
    pk: String,
    //black3_hash: String,
    index_start: u64,
    range_end: u64,
}

async fn post_file(Path(pk): Path<String>, body: Bytes) -> Result<impl IntoResponse, AppError> {
    let _pk = &Secp256k1PubKey::try_from(pk.as_str())?;
    let Blake3Hash(hash) = write_file(_pk, &body).await?;
    Ok((StatusCode::OK, hash.to_hex().to_string()))
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

async fn get_slice(my_params: Query<FileSlice>) -> Result<impl IntoResponse, AppError> {
    debug!("my_params :: blake {:?} ", &my_params.pk);
    //debug!("my_params :: blake {:?} ", &my_params.black3_hash); // this must be derived locally
    debug!("my_params :: start {:?} ", &my_params.index_start);
    debug!("my_params :: end {:?} ", &my_params.range_end);

    //let slice_start = 65536;
    // let slice_len = 8192;
    //blake3_hash: &Blake3Hash,
    //let pk = Secp256k1PubKey::try_from(my_params.pk.as_str())?;

    // WHERE TO GET BLAKE3 HASH FORM?
    // TRY FROM CATALOG
    //let black3_hash =
    //let read_the_slice = read_slices(&pk, my_params.index_start, my_params.range_end).await;
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
        .route("/retrieve/:pk/:blake3_hash", get(get_file))
        .route("/slice/", get(get_slice))
        // .route("/catalog/:blake3_hash", get(get_catalog))
        // .route("/raw/:bao_hash", get(get_raw))
        .layer(CorsLayer::permissive());

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
