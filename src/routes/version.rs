use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;

use crate::routes::full_body;

pub async fn get() -> Result<Response<BoxBody<Bytes, Infallible>>> {
    let version = format!("{} {}\n", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    Ok(Response::builder()
        .header("Content-Type", "text/plain")
        .body(full_body(&version))
        .unwrap())
}
