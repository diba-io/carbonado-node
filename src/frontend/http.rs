use std::{env, net::SocketAddr, str::FromStr};

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use log::info;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{read_file, write_file},
    prelude::*,
};

async fn post_file(Path(pk): Path<String>, body: Bytes) -> Result<impl IntoResponse, AppError> {
    let pk = Secp256k1PubKey::try_from(pk.as_str())?;
    let Blake3Hash(hash) = write_file(pk, &body).await?;

    Ok((StatusCode::OK, hash.to_hex().to_string()))
}

#[axum_macros::debug_handler]
async fn get_file(Path(blake3_hash): Path<String>) -> Result<impl IntoResponse, AppError> {
    let blake3_hash = Blake3Hash(blake3::Hash::from_str(&blake3_hash)?);
    let file_bytes = read_file(blake3_hash).await?;

    Ok((StatusCode::OK, file_bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "debug");
    }

    pretty_env_logger::init();

    let app = Router::new()
        .route("/file/:pk", post(post_file))
        .route("/file/:blake3_hash", get(get_file))
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
