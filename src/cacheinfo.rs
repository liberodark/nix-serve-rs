use anyhow::Result;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::Config;
use crate::routes::full_body;

/// Handles the /nix-cache-info endpoint which provides basic information about
/// the Nix binary cache to clients.
pub async fn get(config: &Arc<Config>) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    // Create a formatted text response with cache info
    let info = format!(
        "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
        config.store.virtual_store(),
        config.priority
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/x-nix-cache-info")
        .body(full_body(&info))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::routes::full_body;
    use crate::store::Store;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_get_cache_info() {
        // Create a test config
        let mut config = Config::default();
        config.priority = 42;
        config.store = Store::new("/test/store".to_string(), None);

        let config = Arc::new(config);

        // Call the handler
        let resp = get(&config).await.unwrap();

        // Verify the response
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "text/x-nix-cache-info"
        );

        // Extract and check the body
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("StoreDir: /test/store"));
        assert!(body_str.contains("WantMassQuery: 1"));
        assert!(body_str.contains("Priority: 42"));
    }
}
