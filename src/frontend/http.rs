use std::sync::Arc;
use std::{net::SocketAddr, str::FromStr};

use tokio::sync::Mutex;

use anyhow::{anyhow, Error, Result};

use axum::body::Bytes;
use axum::{
    body::StreamBody,
    extract::{BodyStream, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};

use bytes::BytesMut;
use futures_util::StreamExt;
use infer::{self};
use log::{debug, info, trace};
use percent_encoding::{percent_decode_str, utf8_percent_encode, FORM};
use secp256k1::PublicKey;
use tower_http::cors::CorsLayer;

use crate::{
    backend::fs::{delete_file, read_file, write_file},
    config::{node_shared_secret, SYS_CFG},
    prelude::*,
};

// ...
pub async fn write_file_handler(
    pk: &str,
    body: BodyStream,
    name: Option<String>,
) -> Result<String> {
    let pk = &Secp256k1PubKey::try_from(pk)?;

    let is_mime_type = Arc::new(Mutex::new("attempt_for_mime_type_is?".to_string()));

    let (file_stream_result, mime_type) = tokio::join!(
        async {
            let mut remainder = BytesMut::with_capacity(SEGMENT_SIZE * 2);
            let mut body_stream = body;
            let mut buffer = Vec::new();
            let mut file_data = Vec::new();

            while remainder.len() < SEGMENT_SIZE {
                if let Some(chunk) = body_stream.next().await {
                    let bytes = match chunk {
                        Ok(bytes) => bytes,
                        Err(_) => todo!(),
                    };

                    buffer.extend_from_slice(&bytes);

                    let kind = infer::get(&buffer);
                    let mime_type = {
                        debug!("INNER Before locking is_mime_type");
                        let mut mime_hasher_guard = is_mime_type.lock().await;
                        debug!("INNER After locking is_mime_type");

                        let calculated_mime_type = match kind {
                            Some(mime_type) => {
                                *mime_hasher_guard = mime_type.mime_type().to_string();
                                mime_type.mime_type().to_string()
                            }
                            None => "application/octet-stream".to_string(),
                        };

                        calculated_mime_type
                    };

                    debug!(">>>>>>>>>>>>>> ================ >> FROM HTTP {}", mime_type);

                    remainder.extend(bytes);

                    if remainder.len() >= SEGMENT_SIZE {
                        let segment = buffer[0..SEGMENT_SIZE].to_vec();
                        file_data.push(Bytes::from(segment));
                        buffer = buffer[SEGMENT_SIZE..].to_vec();
                    }
                } else {
                    trace!("No more segments in Body Stream");
                    return Ok::<Option<Vec<Bytes>>, Error>(None);
                }
            }
            trace!("Unexpected while short-circuit");

            Ok(Some(file_data))
        },
        async {
            let mime_type;
            {
                let mime_hasher_guard = is_mime_type.lock().await;
                mime_type = mime_hasher_guard.clone();
            }

            let mime_type = mime_type.as_str();

            Ok::<Result<String, Error>, Error>(Ok(mime_type.to_string()))
        }
    );

    let mime_type = mime_type?;
    let file_data = file_stream_result?.unwrap_or_default();

    let file_stream = futures_util::stream::iter(file_data.into_iter().map(Ok::<_, Error>));

    let map_stream = Box::pin(file_stream).map(|vec_bytes| {
        let bytes = vec_bytes.into_iter().flatten();
        let collected_bytes: Vec<u8> = bytes.map(|chunk| chunk.to_be()).collect::<Vec<_>>();

        Ok(Bytes::from(collected_bytes))
    });

    let Blake3Hash(hash) = write_file(pk, Box::pin(map_stream), name, &mime_type.unwrap()).await?;

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
