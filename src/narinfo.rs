use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

use crate::config::Config;
use crate::routes::{full_body, not_found};
use crate::signing::{convert_base16_to_nix32, fingerprint_path};
use crate::store::Store;

/// Query parameters for narinfo requests
#[derive(Debug, Deserialize, Default)]
pub struct NarInfoQuery {
    json: Option<String>,
}

/// Parse query string for narinfo requests
fn parse_query(query: Option<&str>) -> NarInfoQuery {
    match query {
        Some(q) => {
            // Simple query parser - look for json=1 or json=true
            if q.contains("json=1") || q.contains("json=true") {
                NarInfoQuery {
                    json: Some("1".to_string()),
                }
            } else {
                NarInfoQuery::default()
            }
        }
        None => NarInfoQuery::default(),
    }
}

/// Narinfo structure - represents the metadata for a NAR file
#[derive(Debug, Serialize)]
struct NarInfo {
    store_path: String,
    url: String,
    compression: String,
    file_hash: String,
    file_size: u64,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
    signatures: Vec<String>,
    ca: Option<String>,
}

/// Extract the filename from a path
fn extract_filename(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|v| v.to_str().map(ToString::to_string))
}

/// Format a narinfo as a text response
fn format_narinfo_txt(narinfo: &NarInfo) -> String {
    let mut lines = vec![
        format!("StorePath: {}", narinfo.store_path),
        format!("URL: {}", narinfo.url),
        format!("Compression: {}", narinfo.compression),
        format!("FileHash: {}", narinfo.nar_hash),
        format!("FileSize: {}", narinfo.file_size),
        format!("NarHash: {}", narinfo.nar_hash),
        format!("NarSize: {}", narinfo.nar_size),
    ];

    if !narinfo.references.is_empty() {
        lines.push(format!("References: {}", narinfo.references.join(" ")));
    }

    if let Some(ref deriver) = narinfo.deriver {
        lines.push(format!("Deriver: {}", deriver));
    }

    for sig in &narinfo.signatures {
        lines.push(format!("Sig: {}", sig));
    }

    if let Some(ref ca) = narinfo.ca {
        lines.push(format!("CA: {}", ca));
    }

    lines.push(String::new());
    lines.join("\n")
}

/// Generate narinfo data for a store path
async fn generate_narinfo(
    store: &Arc<Store>,
    store_path: &str,
    hash: &str,
    config: &Config,
) -> Result<Option<NarInfo>> {
    // Query path info from daemon
    let path_info = match store
        .daemon
        .lock()
        .await
        .query_path_info(store_path)
        .await?
        .path
    {
        Some(info) => info,
        None => return Ok(None),
    };

    debug!("Raw hash from daemon: {}", path_info.hash);

    // Convert hash to base32 if needed
    let (hash_prefix, hash_value) = if path_info.hash.starts_with("sha256:") {
        let parts: Vec<&str> = path_info.hash.splitn(2, ':').collect();
        (parts[0], parts[1])
    } else {
        // Convertir String en &str avec as_str()
        ("sha256", path_info.hash.as_str())
    };

    let nar_hash_base32 =
        convert_base16_to_nix32(hash_value).context("Failed to convert hash to base32")?;

    debug!("Converted hash to base32: {}", nar_hash_base32);

    let nar_hash = format!("{}:{}", hash_prefix, nar_hash_base32);

    // Determine compression and URL
    let (compression, url) = if config.compress_nars {
        (
            config.compression_format.clone(),
            format!(
                "nar/{}.nar.{}?hash={}",
                nar_hash_base32, config.compression_format, hash
            ),
        )
    } else {
        (
            "none".to_string(),
            format!("nar/{}.nar?hash={}", nar_hash_base32, hash),
        )
    };

    // Process references - extract basenames
    let references = path_info
        .references
        .iter()
        .filter_map(|r| extract_filename(r))
        .collect::<Vec<_>>();

    // Get deriver basename if present
    let deriver = if path_info.deriver.is_empty() {
        None
    } else {
        extract_filename(&path_info.deriver)
    };

    // Create narinfo structure
    let mut narinfo = NarInfo {
        store_path: store_path.to_string(),
        url,
        compression,
        file_hash: nar_hash.clone(),
        file_size: path_info.nar_size,
        nar_hash,
        nar_size: path_info.nar_size,
        references,
        deriver,
        signatures: Vec::new(),
        ca: path_info.content_address,
    };

    // Add signatures if we have signing keys
    if !config.signing_keys.is_empty() {
        let refs = path_info.references.clone();

        if let Some(fingerprint) = fingerprint_path(
            &config.virtual_store,
            store_path,
            &narinfo.nar_hash,
            narinfo.nar_size,
            &refs,
        )? {
            for key in &config.signing_keys {
                narinfo
                    .signatures
                    .push(crate::signing::sign_string(key, &fingerprint));
            }
        }
    } else if !path_info.sigs.is_empty() {
        // If we don't have keys but the daemon has signatures, use those
        narinfo.signatures = path_info.sigs;
    }

    Ok(Some(narinfo))
}

/// Handle GET requests for narinfo files
pub async fn get(
    hash: &str,
    query: Option<&str>,
    config: &Arc<Config>,
    store: &Arc<Store>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("NARInfo request for hash: {}", hash);

    // Validate hash format (32 chars, hex)
    if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .body(full_body("Invalid hash format"))
            .unwrap());
    }

    // Parse query parameters
    let params = parse_query(query);

    // Query path from hash part
    let store_path = match store
        .daemon
        .lock()
        .await
        .query_path_from_hash_part(hash)
        .await?
    {
        Some(path) => path,
        None => return Ok(not_found()),
    };

    debug!("Found store path: {}", store_path);

    // Generate narinfo
    let narinfo = match generate_narinfo(store, &store_path, hash, config).await? {
        Some(info) => info,
        None => return Ok(not_found()),
    };

    // Either format as JSON or text based on query parameter
    if params.json.is_some() {
        debug!("Serving narinfo as JSON");
        // Convert to JSON and return
        let json_str = serde_json::to_string_pretty(&narinfo)?;

        Ok(Response::builder()
            .header("Content-Type", "application/json")
            .header("Cache-Control", "max-age=86400") // 1 day
            .body(full_body(&json_str))
            .unwrap())
    } else {
        debug!("Serving narinfo as text");
        // Format as text and return
        let text = format_narinfo_txt(&narinfo);

        Ok(Response::builder()
            .header("Content-Type", "text/x-nix-narinfo")
            .header("Nix-Link", &narinfo.url)
            .header("Cache-Control", "max-age=86400") // 1 day
            .body(full_body(&text))
            .unwrap())
    }
}

/// Handle PUT requests for narinfo files
pub async fn put(
    hash: &str,
    body: Bytes,
    config: &Arc<Config>,
    _store: &Arc<Store>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Processing narinfo upload for hash: {}", hash);

    // Validate hash format
    if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .body(full_body("Invalid hash format"))
            .unwrap());
    }

    // Parse the narinfo content
    let content = std::str::from_utf8(&body).context("Invalid UTF-8 in narinfo content")?;

    // Basic validation of content
    let mut found_store_path = false;
    let mut found_nar_hash = false;
    let mut found_nar_size = false;

    for line in content.lines() {
        if line.starts_with("StorePath: ") {
            found_store_path = true;
        } else if line.starts_with("NarHash: ") {
            found_nar_hash = true;
        } else if line.starts_with("NarSize: ") {
            found_nar_size = true;
        }
    }

    if !found_store_path || !found_nar_hash || !found_nar_size {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .body(full_body("Missing required fields in narinfo"))
            .unwrap());
    }

    // Determine where to store the narinfo file
    let narinfo_dir = PathBuf::from(config.real_store())
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine parent directory of store"))?
        .to_owned();

    debug!("Storing narinfo in directory: {}", narinfo_dir.display());

    // Make sure the directory exists
    tokio::fs::create_dir_all(&narinfo_dir)
        .await
        .context("Failed to create narinfo directory")?;

    // Write the narinfo file
    let narinfo_path = narinfo_dir.join(format!("{}.narinfo", hash));
    tokio::fs::write(&narinfo_path, content)
        .await
        .context("Failed to write narinfo file")?;

    info!(
        "Successfully stored narinfo for {} at {}",
        hash,
        narinfo_path.display()
    );

    // Return success
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(full_body("OK"))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query() {
        // Test with JSON parameter
        let query = "json=1&other=value";
        let params = parse_query(Some(query));
        assert!(params.json.is_some());

        // Test without JSON parameter
        let query = "other=value";
        let params = parse_query(Some(query));
        assert!(params.json.is_none());

        // Test with no query
        let params = parse_query(None);
        assert!(params.json.is_none());
    }

    #[test]
    fn test_extract_filename() {
        assert_eq!(
            extract_filename("/nix/store/abcdef123456-test"),
            Some("abcdef123456-test".to_string())
        );
        assert_eq!(extract_filename(""), None);
    }

    #[test]
    fn test_format_narinfo_txt() {
        let narinfo = NarInfo {
            store_path: "/nix/store/abcdef123456-test".to_string(),
            url: "nar/hash.nar".to_string(),
            compression: "none".to_string(),
            file_hash: "sha256:hash".to_string(),
            file_size: 1234,
            nar_hash: "sha256:hash".to_string(),
            nar_size: 1234,
            references: vec!["dep1".to_string(), "dep2".to_string()],
            deriver: Some("test.drv".to_string()),
            signatures: vec!["signature".to_string()],
            ca: None,
        };

        let text = format_narinfo_txt(&narinfo);

        // Verify that the text contains all the expected fields
        assert!(text.contains("StorePath: /nix/store/abcdef123456-test"));
        assert!(text.contains("URL: nar/hash.nar"));
        assert!(text.contains("Compression: none"));
        assert!(text.contains("FileHash: sha256:hash"));
        assert!(text.contains("FileSize: 1234"));
        assert!(text.contains("NarHash: sha256:hash"));
        assert!(text.contains("NarSize: 1234"));
        assert!(text.contains("References: dep1 dep2"));
        assert!(text.contains("Deriver: test.drv"));
        assert!(text.contains("Sig: signature"));
    }
}
