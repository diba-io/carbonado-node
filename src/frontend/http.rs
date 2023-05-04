use std::{net::SocketAddr, str::FromStr};

use anyhow::Result;
use axum::{
    extract::{BodyStream, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use futures_util::{
    stream::{self},
    StreamExt,
};
use log::info;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, write_file, FileStream},
    config::SYS_CFG,
    prelude::*,
};

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
