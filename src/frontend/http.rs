use std::sync::Arc;
use std::{net::SocketAddr, str::FromStr};
use tokio::sync::watch;

use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use bytes::BytesMut;
use file_format::FileFormat;

use futures_util::{stream, StreamExt};
use log::{debug, info};
use percent_encoding::{percent_decode_str, utf8_percent_encode, FORM};
use secp256k1::PublicKey;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, write_file, FileStream},
    config::{node_shared_secret, SYS_CFG},
    prelude::*,
};

async fn write_file_handler(pk: &str, body: Body, name: Option<String>) -> Result<String> {
    let pk = &Secp256k1PubKey::try_from(pk)?;

    let name_clone = name.clone().unwrap_or("Not Named".to_string());
    let extension = name_clone.split('.').last().unwrap_or_default();
    if extension.is_empty() {
        debug!(">>>>>> NO EXETENSION FROM NAME {}", extension);
    } else {
        debug!(">>>>>> EXETENSION FROM NAME {}", extension);
    }

    // Create a watch channel for MIME type updates
    let (mime_type_sender, mime_type_receiver) = watch::channel("init_mime_type".to_string());

    // Wrap the sender in an Arc
    let mime_type_sender = Arc::new(mime_type_sender);

    // Process the file stream and determine the MIME type
    let file_stream: FileStream = stream::try_unfold(
        (
            body.into_data_stream(),
            BytesMut::with_capacity(SEGMENT_SIZE * 2),
        ),
        move |(mut body_stream, mut remainder)| {
            let mime_type_sender = mime_type_sender.clone();
            async move {
                // Stream processing logic...
                while let Some(chunk) = body_stream.next().await {
                    let bytes = chunk?;

                    remainder.extend_from_slice(&bytes);

                    let format = FileFormat::from_bytes(&remainder);
                    let stage_mime_type = format.media_type().to_string();

                    //let mime_type = stage_mime_type;
                    let _ = mime_type_sender.send(stage_mime_type.clone());

                    // Determine MIME type and store in shared state
                    if remainder.len() >= SEGMENT_SIZE {
                        let segment = remainder.split_to(SEGMENT_SIZE);
                        return Ok(Some((segment.freeze(), (body_stream, remainder))));
                    }
                }
                // Handle the case where the stream has ended but there's unprocessed data
                if !remainder.is_empty() {
                    let final_chunk = remainder.split_to(remainder.len());

                    // Ensure MIME type is sent for the final chunk
                    let format = FileFormat::from_bytes(&final_chunk);
                    let final_mime_type = format.media_type().to_string();
                    let _ = mime_type_sender.send(final_mime_type);

                    return Ok(Some((final_chunk.freeze(), (body_stream, BytesMut::new()))));
                }

                Ok(None)
            }
        },
    )
    .boxed();

    // Call write_file with the receiver part of the channel
    let Blake3Hash(hash) = write_file(pk, file_stream, name, mime_type_receiver).await?;

    Ok(hash.to_hex().to_string())
}

#[axum_macros::debug_handler]
async fn post_file(Path(pk): Path<String>, body: Body) -> Result<impl IntoResponse, AppError> {
    debug!("post_file called with {pk}");

    let hash = write_file_handler(&pk, body, None).await?;

    Ok((StatusCode::OK, hash))
}

#[axum_macros::debug_handler]
async fn post_file_named(
    Path((pk, name)): Path<(String, String)>,
    body: Body,
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

    Ok((StatusCode::OK, Body::from_stream(file_stream)))
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

    Ok((StatusCode::OK, Body::from_stream(file_stream)))
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
        .route("/store_named/:pk/:name", post(post_file_named))
        .route("/retrieve/:pk/:blake3_hash", get(get_file))
        .route("/retrieve_named/:pk/:name", get(get_file_named))
        .route("/key/:pk", get(key))
        // .route("/catalog/:blake3_hash", get(get_catalog))
        // .route("/raw/:bao_hash", get(get_raw))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], SYS_CFG.http_port));

    info!("carbonado-node HTTP frontend successfully running at {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

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
