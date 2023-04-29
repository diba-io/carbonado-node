use anyhow::Result;
use std::fs;
use std::sync::RwLock;
use std::{net::SocketAddr, str::FromStr};
//use axum::extract::FromRequestParts;
use axum::{
    body::Bytes,
    extract::Multipart,
    extract::Path,
    extract::Query,
    http::{header::CONTENT_TYPE, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use log::{debug, info};

use crate::{
    backend::fs::{delete_file, read_file, read_slices, write_file},
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

async fn post_file<'a>(
    Path(pk): Path<String>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        //let data: Bytes = field.bytes().await.unwrap();
        let data: Bytes = field.bytes().await.unwrap();

        debug!("Length of `{}` is {} bytes", name, data.len());
        debug!("DATA of `{}` is {:?} DATA", name, data);

        let _pk = &Secp256k1PubKey::try_from(pk.as_str())?;

        let path = "file/".to_owned() + "body_test" + ".png";
        debug!(">>> file body_test:: {}", path);
        fs::write(path, &data)?;

        let hash = write_file(_pk, &data).await?;

        // store hash into lock to get a response body for carbonado client
        let hash_to_string = hash.to_string();
        let mut w = LOCK.write().unwrap();
        *w = hash_to_string;
    }

    // let body = _body;
    //post_file..Write file into dir file for test

    Ok((StatusCode::OK, "my_hash"))
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
    let _file_bytes = read_file(&pk, &blake3_hash).await?;

    Ok((StatusCode::OK, _file_bytes))
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
