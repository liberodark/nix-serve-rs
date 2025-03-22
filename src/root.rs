use anyhow::Result;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::Config;
use crate::routes::full_body;

const BOOTSTRAP_CSS: &str = r#"<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
      integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65"
      crossorigin="anonymous">"#;

/// Handle the root endpoint (/) which displays a simple HTML page
/// with information about the Nix binary cache.
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
                    Powered by <a href="https://github.com/liberodark/nix-serve-rs">nix-serve-rs</a> v{version}
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
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(full_body(&html))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::Store;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_root_endpoint() {
        // Create a test config
        let mut config = Config::default();
        config.priority = 42;
        config.virtual_store = "/test/store".to_string();
        config.store = Store::new("/test/store".to_string(), None);

        let config = Arc::new(config);

        // Call the handler
        let resp = get(&config).await.unwrap();

        // Verify response code and content type
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "text/html; charset=utf-8"
        );

        // Check content
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("Store Dir: /test/store"));
        assert!(body_str.contains("Want Mass Query: 1"));
        assert!(body_str.contains("Priority: 42"));
        assert!(body_str.contains("Powered by"));
        assert!(body_str.contains("nix-serve-rs"));
    }
}
