use std::{net::SocketAddr, str::FromStr};

use anyhow::Result;
use axum::{
    body::StreamBody,
    extract::{BodyStream, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use bytes::BytesMut;
use futures_util::{stream, StreamExt};
use log::{debug, info, trace};
use secp256k1::PublicKey;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, write_file, FileStream},
    config::{node_shared_secret, SYS_CFG},
    prelude::*,
};

#[axum_macros::debug_handler]
async fn post_file(
    Path(pk): Path<String>,
    body: BodyStream,
) -> Result<impl IntoResponse, AppError> {
    debug!("post_file called with {pk}");
    let pk = &Secp256k1PubKey::try_from(pk.as_str())?;

    let file_stream: FileStream = stream::try_unfold(
        (body, BytesMut::with_capacity(SEGMENT_SIZE * 2)),
        |(mut body_stream, mut remainder)| async {
            while remainder.len() < SEGMENT_SIZE {
                if let Some(chunk) = body_stream.next().await {
                    let bytes = chunk?;
                    remainder.extend(bytes);

                    if remainder.len() >= SEGMENT_SIZE {
                        let segment = remainder.split_to(SEGMENT_SIZE);
                        trace!("Stream 1MB segment");
                        return Ok(Some((segment.freeze(), (body_stream, remainder))));
                    }
                } else {
                    trace!("No more segments in Body Stream");
                    return Ok(None);
                }
            }
            trace!("Unexpected while short-circuit");
            Ok(None)
        },
    )
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
    let file_stream = read_file(&pk, &blake3_hash)?;

    Ok((StatusCode::OK, StreamBody::new(file_stream)))
}

#[axum_macros::debug_handler]
async fn remove_file(
    Path((pk, blake3_hash)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let pk = Secp256k1PubKey::try_from(pk.as_str())?;
    delete_file(pk, blake3_hash.as_bytes())?;
    Ok((StatusCode::OK, blake3_hash))
}

async fn key(Path(pk): Path<String>) -> Result<impl IntoResponse, AppError> {
    let pk = PublicKey::from_str(&pk)?;

    let ss = node_shared_secret(&pk)?;
    let ss = ss.display_secret();

    Ok(ss.to_string())
}

pub async fn start() -> Result<()> {
    let app = Router::new()
        .route("/remove/:pk/:blake3_hash", delete(remove_file))
        .route("/store/:pk", post(post_file))
        .route("/retrieve/:pk/:blake3_hash", get(get_file))
        .route("/key/:pk", get(key))
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
