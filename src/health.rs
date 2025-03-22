use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;

use crate::routes::full_body;

/// Health check endpoint that returns a simple "OK" response.
/// This is useful for monitoring systems and load balancers to verify
/// that the service is running properly.
pub async fn get() -> Result<Response<BoxBody<Bytes, Infallible>>> {
    Ok(Response::builder()
        .header("Content-Type", "text/plain")
        .body(full_body("OK\n"))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        // Call the health endpoint
        let response = get().await.unwrap();

        // Check response status
        assert_eq!(response.status(), StatusCode::OK);

        // Check content type
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/plain"
        );

        // Check response body
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("OK\n"));
    }
}
