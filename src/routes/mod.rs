pub mod build_log;
pub mod cache_info;
pub mod health;
pub mod nar;
pub mod narinfo;
pub mod root;
pub mod version;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;

pub fn full_body(body: &str) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from(body.to_string())).boxed()
}

pub fn not_found() -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "text/plain")
        .header("Cache-Control", "no-store")
        .body(full_body("Not Found"))
        .unwrap()
}

pub fn internal_error(msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("Content-Type", "text/plain")
        .header("Cache-Control", "no-store")
        .body(full_body(&format!("Internal Server Error: {}", msg)))
        .unwrap()
}
