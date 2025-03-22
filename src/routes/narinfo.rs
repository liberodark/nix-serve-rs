use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::config::Config;
use crate::crypto::signing::{convert_base16_to_nix32, fingerprint_path};
use crate::nix::store::NixStore;
use crate::routes::{full_body, not_found};

/// NARInfo structure representing a NAR file's metadata
#[derive(Debug)]
struct NarInfo {
    store_path: String,
    url: String,
    compression: String,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
    sigs: Vec<String>,
    ca: Option<String>,
}

/// Extract the filename from a path
fn extract_filename(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|v| v.to_str().map(ToString::to_string))
}

/// Format a NARInfo as a text response
fn format_narinfo_txt(narinfo: &NarInfo) -> String {
    let mut lines = vec![
        format!("StorePath: {}", narinfo.store_path),
        format!("URL: {}", narinfo.url),
        format!("Compression: {}", narinfo.compression),
        format!("NarHash: {}", narinfo.nar_hash),
        format!("NarSize: {}", narinfo.nar_size),
    ];

    if !narinfo.references.is_empty() {
        lines.push(format!("References: {}", narinfo.references.join(" ")));
    }

    if let Some(ref deriver) = narinfo.deriver {
        lines.push(format!("Deriver: {}", deriver));
    }

    for sig in &narinfo.sigs {
        lines.push(format!("Sig: {}", sig));
    }

    if let Some(ref ca) = narinfo.ca {
        lines.push(format!("CA: {}", ca));
    }

    lines.push(String::new());
    lines.join("\n")
}

/// Query path info and convert to NARInfo
async fn query_narinfo(
    store: &NixStore,
    store_path: &str,
    hash: &str,
    config: &Config,
) -> Result<Option<NarInfo>> {
    let path_info = match store.query_path_info(store_path).await? {
        Some(info) => info,
        None => return Ok(None),
    };

    let nar_hash = match convert_base16_to_nix32(&path_info.hash) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to convert hash: {}", e);
            return Ok(None);
        }
    };

    // Determine compression and URL path
    let (compression, url) = if config.compress_nars {
        (
            config.compression_format.clone(),
            format!(
                "nar/{}-{}.nar.{}",
                hash, nar_hash, config.compression_format
            ),
        )
    } else {
        ("none".to_string(), format!("nar/{}-{}.nar", hash, nar_hash))
    };

    let mut narinfo = NarInfo {
        store_path: store_path.to_string(),
        url,
        compression,
        nar_hash: format!("sha256:{}", nar_hash),
        nar_size: path_info.nar_size,
        references: Vec::new(),
        deriver: None,
        sigs: Vec::new(),
        ca: path_info.content_address,
    };

    // Add the deriver if present
    if let Some(ref deriver) = path_info.deriver {
        narinfo.deriver = extract_filename(deriver);
    }

    // Process references
    if !path_info.references.is_empty() {
        narinfo.references = path_info
            .references
            .iter()
            .filter_map(|r| extract_filename(r))
            .collect::<Vec<_>>();
    }

    // Apply signatures
    let refs = path_info.references.clone();
    if !config.signing_keys.is_empty() {
        let fingerprint = fingerprint_path(
            &config.virtual_store,
            store_path,
            &narinfo.nar_hash,
            narinfo.nar_size,
            &refs,
        )?;

        if let Some(ref fp) = fingerprint {
            for key in &config.signing_keys {
                narinfo.sigs.push(key.sign(fp)?);
            }
        }
    } else if !path_info.sigs.is_empty() {
        narinfo.sigs = path_info.sigs;
    }

    Ok(Some(narinfo))
}

/// NARInfo endpoint
pub async fn get(
    hash: &str,
    query: Option<&str>,
    config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("NAR info request for hash: {}", hash);

    // Check if JSON output is requested
    let json_output = query
        .map(|q| q.contains("json=1") || q.contains("json=true"))
        .unwrap_or(false);

    // Query path from hash part
    let store_path = match store.query_path_from_hash_part(hash).await? {
        Some(path) => path,
        None => return Ok(not_found()),
    };

    // Get NARInfo
    let narinfo = match query_narinfo(store, &store_path, hash, config).await? {
        Some(info) => info,
        None => return Ok(not_found()),
    };

    // Either format as JSON or text based on query parameter
    if json_output {
        // Convert to a structure that can be serialized to JSON
        let json_output = serde_json::json!({
            "storePath": narinfo.store_path,
            "url": narinfo.url,
            "compression": narinfo.compression,
            "narHash": narinfo.nar_hash,
            "narSize": narinfo.nar_size,
            "references": narinfo.references,
            "deriver": narinfo.deriver,
            "signatures": narinfo.sigs,
            "ca": narinfo.ca,
        });

        let json_str = serde_json::to_string_pretty(&json_output)?;

        Ok(Response::builder()
            .header("Content-Type", "application/json")
            .header("Cache-Control", "max-age=86400") // 1 day
            .body(full_body(&json_str))
            .unwrap())
    } else {
        // Format and return response as text
        let body = format_narinfo_txt(&narinfo);

        Ok(Response::builder()
            .header("Content-Type", "text/x-nix-narinfo")
            .header("Nix-Link", &narinfo.url)
            .header("Cache-Control", "max-age=86400") // 1 day
            .body(full_body(&body))
            .unwrap())
    }
}

/// Handle PUT requests for narinfo files
pub async fn put(
    hash: &str,
    body: bytes::Bytes,
    config: &Arc<Config>,
    _store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Processing narinfo upload for hash: {}", hash);

    // First, verify the hash is valid
    if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .body(full_body("Invalid hash format"))
            .unwrap());
    }

    // Parse the narinfo content
    let content = std::str::from_utf8(&body)?;
    let lines: Vec<&str> = content.lines().collect();

    // Basic validation of content for logging
    let mut found_store_path = false;
    let mut found_nar_hash = false;
    let mut found_nar_size = false;

    for line in &lines {
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
            .status(http::StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .body(full_body("Missing required fields in narinfo"))
            .unwrap());
    }

    // Determine where to store the narinfo file
    let store_root = Path::new(config.real_store());
    let narinfo_dir = if store_root.is_absolute() {
        store_root
            .parent()
            .ok_or_else(|| {
                anyhow::anyhow!("Cannot determine narinfo directory, real_store has no parent")
            })?
            .to_path_buf()
    } else {
        store_root.to_path_buf()
    };

    // Create parent directories if they don't exist
    if !narinfo_dir.exists() {
        tokio::fs::create_dir_all(&narinfo_dir).await?;
    }

    // Write the narinfo file
    let narinfo_path = narinfo_dir.join(format!("{}.narinfo", hash));
    tokio::fs::write(&narinfo_path, content).await?;

    info!("Successfully processed narinfo upload for {}", hash);

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(full_body("OK"))
        .unwrap())
}
