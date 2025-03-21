use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::Config;
use crate::routes::full_body;

const BOOTSTRAP_CSS: &str = r#"<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
      integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65"
      crossorigin="anonymous">"#;

pub async fn get(config: &Arc<Config>) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Nix binary cache (nix-serve-rs {version})</title>
    {bootstrap_css}
</head>
<body>
    <div class="container mt-3">
        <div class="row justify-content-md-center">
            <div class="col-md-auto">
                <p class="lead">
                    This service provides a "binary cache" for the
                    <a href="https://nixos.org/nix/">Nix package manager</a>
                </p>
            </div>
        </div>
        <hr>
        <div class="row">
            <div class="col text-center">
                <h4 class="mb-3">Cache Info</h4>
                <p>Store Dir: {store_dir}</p>
                <p>Want Mass Query: 1</p>
                <p>Priority: {priority}</p>
            </div>
        </div>
        <hr>
        <div class="row">
            <div class="col text-center">
                <small class="d-block mb-3 text-muted">
                    Powered by <a href="https://github.com/yourusername/nix-serve-rs">nix-serve-rs</a>
                </small>
            </div>
        </div>
    </div>
</body>
</html>
"#,
        version = env!("CARGO_PKG_VERSION"),
        bootstrap_css = BOOTSTRAP_CSS,
        store_dir = config.virtual_store,
        priority = config.priority
    );

    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .body(full_body(&html))
        .unwrap())
}
