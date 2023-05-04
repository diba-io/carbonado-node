use std::{net::SocketAddr, str::FromStr, sync::RwLock};

use anyhow::Result;
use axum::{
    body::StreamBody,
    extract::{BodyStream, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use bytes::BytesMut;
use futures_util::{stream, StreamExt};
use log::{debug, info, trace};
use secp256k1::PublicKey;
use serde::Deserialize;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, read_slices, write_file, FileStream},
    config::{node_shared_secret, SYS_CFG},
    prelude::*,
};

static LOCK: std::sync::RwLock<std::string::String> = RwLock::new(String::new());

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

// TODO: This seems unnecessary, and could introduce concurrency and security issues
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
    let file_stream = read_file(&pk, &blake3_hash)?;

    Ok((StatusCode::OK, StreamBody::new(file_stream)))
}

/* TODO: Reading slices this way will be very inefficient. Ideally only the specific segment containing the slice is decoded. As a result, this will not be able to make use of read_file.
#[derive(Deserialize, std::fmt::Debug)]
struct FileSlice {
    pk: String,
    black3_hash: String,
    index_start: u64,
    range_end: u16,
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
} */

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
        .route("/last_hash/:pk", get(get_last_hash))
        .route("/retrieve/:pk/:blake3_hash", get(get_file))
        // .route("/slice/", get(get_slice))
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
