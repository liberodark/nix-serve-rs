use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;

use crate::routes::full_body;

/// Handle the /version endpoint which returns the package name and version number.
/// This is useful for monitoring and debugging to identify which version is running.
pub async fn get() -> Result<Response<BoxBody<Bytes, Infallible>>> {
    let version = format!("{} {}\n", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    Ok(Response::builder()
        .header("Content-Type", "text/plain")
        .body(full_body(&version))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_version_endpoint() {
        // Call the version endpoint
        let resp = get().await.unwrap();

        // Check response status and content type
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Type").unwrap(), "text/plain");

        // Check that the response body contains the expected version info
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // The expected format is "{PKG_NAME} {PKG_VERSION}\n"
        let expected = format!("{} {}\n", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        assert_eq!(body_str, expected);
    }
}
