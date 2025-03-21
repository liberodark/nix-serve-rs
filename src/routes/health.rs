use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;

use crate::routes::full_body;

pub async fn get() -> Result<Response<BoxBody<Bytes, Infallible>>> {
    Ok(Response::builder()
        .header("Content-Type", "text/plain")
        .body(full_body("OK\n"))
        .unwrap())
}
