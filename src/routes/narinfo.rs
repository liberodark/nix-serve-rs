use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error};

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

    let mut narinfo = NarInfo {
        store_path: store_path.to_string(),
        url: format!("nar/{}.nar?hash={}", nar_hash, hash),
        compression: "none".to_string(),
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
    config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("NAR info request for hash: {}", hash);

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

    // Format and return response
    let body = format_narinfo_txt(&narinfo);

    Ok(Response::builder()
        .header("Content-Type", "text/x-nix-narinfo")
        .header("Nix-Link", &narinfo.url)
        .header("Cache-Control", "max-age=86400") // 1 day
        .body(full_body(&body))
        .unwrap())
}
