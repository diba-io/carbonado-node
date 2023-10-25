use std::{net::SocketAddr, str::FromStr};

use anyhow::{anyhow, Result};
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
use percent_encoding::{percent_decode_str, utf8_percent_encode, FORM};
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, write_file, FileStream},
    config::SYS_CFG,
    prelude::*,
};

async fn write_file_handler(pk: &str, body: BodyStream, name: Option<String>) -> Result<String> {
    let pk = &Secp256k1PubKey::try_from(pk)?;

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

    let Blake3Hash(hash) = write_file(pk, file_stream, name).await?;

    Ok(hash.to_hex().to_string())
}

#[axum_macros::debug_handler]
async fn post_file(
    Path(pk): Path<String>,
    body: BodyStream,
) -> Result<impl IntoResponse, AppError> {
    debug!("post_file called with {pk}");

    let hash = write_file_handler(&pk, body, None).await?;

    Ok((StatusCode::OK, hash))
}

#[axum_macros::debug_handler]
async fn post_file_named(
    Path((pk, name)): Path<(String, String)>,
    body: BodyStream,
) -> Result<impl IntoResponse, AppError> {
    debug!("post_file_named called with {pk}/{name}");

    let reencoded =
        utf8_percent_encode(&percent_decode_str(&name).decode_utf8()?, FORM).to_string();

    if name != reencoded {
        return Err(AppError(StatusCode::BAD_REQUEST, anyhow!("Provided file name contains characters that have not been encoded. It should be: {reencoded}")));
    }

    let hash = write_file_handler(&pk, body, Some(name)).await?;

    Ok((StatusCode::OK, hash))
}

#[axum_macros::debug_handler]
async fn get_file(
    Path((pk, blake3_hash)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    debug!("get_file called with {pk}/{blake3_hash}");

    let pk = Secp256k1PubKey::try_from(pk.as_str())?;
    let blake3_hash = Blake3Hash(blake3::Hash::from_str(&blake3_hash)?);

    let file_stream = read_file(&pk, &Lookup::Hash(Hash::Blake3(blake3_hash)))?;

    Ok((StatusCode::OK, StreamBody::new(file_stream)))
}

#[axum_macros::debug_handler]
async fn get_file_named(
    Path((pk, name)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    debug!("get_file_named called with {pk}/{name}");

    let reencoded =
        utf8_percent_encode(&percent_decode_str(&name).decode_utf8()?, FORM).to_string();

    if name != reencoded {
        return Err(AppError(StatusCode::BAD_REQUEST, anyhow!("Provided file name contains characters that have not been encoded. It should be: {reencoded}")));
    }

    let pk = Secp256k1PubKey::try_from(pk.as_str())?;
    let file_stream = read_file(&pk, &Lookup::Name(name))?;

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

async fn id() -> Result<impl IntoResponse, AppError> {
    Ok(SYS_CFG.public_key.to_string())
}

pub async fn start() -> Result<()> {
    let app = Router::new()
        .route("/remove/:pk/:blake3_hash", delete(remove_file))
        .route("/store/:pk", post(post_file))
        .route("/store_named/:pk/:name", post(post_file_named))
        .route("/retrieve/:pk/:blake3_hash", get(get_file))
        .route("/retrieve_named/:pk/:name", get(get_file_named))
        // POST
        .route("/public/hashed/file", post(post_public_hashed_file))
        .route("/public/hashed/catalogs", post(post_public_hashed_catalogs))
        .route("/public/hashed/segments", post(post_public_hashed_segments))
        .route("/public/named/file/:name", post(post_public_named_file))
        .route(
            "/public/named/catalogs/:name",
            post(post_public_named_catalogs),
        )
        .route(
            "/public/named/segments/:name",
            post(post_public_named_segments),
        )
        .route("/private/hashed/file", post(post_private_hashed_file))
        .route(
            "/private/hashed/catalogs",
            post(post_private_hashed_catalogs),
        )
        .route(
            "/private/hashed/segments",
            post(post_private_hashed_segments),
        )
        .route("/private/named/file/:name", post(post_private_named_file))
        .route(
            "/private/named/catalogs/:name",
            post(post_private_named_catalogs),
        )
        .route(
            "/private/named/segments/:name",
            post(post_private_named_segments),
        )
        // GET
        .route("/public/hashed/file", get(get_public_hashed_file))
        .route("/public/hashed/catalogs", get(get_public_hashed_catalogs))
        .route("/public/hashed/segments", get(get_public_hashed_segments))
        .route("/public/named/file", get(get_public_named_file))
        .route("/public/named/catalogs", get(get_public_named_catalogs))
        .route("/public/named/segments", get(get_public_named_segments))
        .route("/private/hashed/file", get(get_private_hashed_file))
        .route("/private/hashed/catalogs", get(get_private_hashed_catalogs))
        .route("/private/hashed/segments", get(get_private_hashed_segments))
        .route("/private/named/file", get(get_private_named_file))
        .route("/private/named/catalogs", get(get_private_named_catalogs))
        .route("/private/named/segments", get(get_private_named_segments))
        .route("/id", get(id))
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
struct AppError(StatusCode, anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("Something went wrong: {}", self.1)).into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, err.into())
    }
}
