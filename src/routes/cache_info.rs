use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::Config;
use crate::routes::full_body;

pub async fn get(config: &Arc<Config>) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    let info = format!(
        "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
        config.virtual_store, config.priority
    );

    Ok(Response::builder()
        .header("Content-Type", "text/x-nix-cache-info")
        .body(full_body(&info))
        .unwrap())
}
