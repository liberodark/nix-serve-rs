use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::StreamExt;
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use hyper::body::Frame;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error};

use crate::config::Config;
use crate::crypto::signing::convert_base16_to_nix32;
use crate::nix::nar;
use crate::nix::store::NixStore;
use crate::routes::{full_body, internal_error, not_found};

/// Parse the query string for a NAR request
fn parse_query(query: Option<&str>) -> Option<String> {
    query.and_then(|q| {
        let pairs = q.split('&').collect::<Vec<_>>();
        for pair in pairs {
            if let Some((key, val)) = pair.split_once('=') {
                if key == "hash" {
                    return Some(val.to_string());
                }
            }
        }
        None
    })
}

/// Parse the NAR URL path
fn parse_nar_path(path: &str) -> Result<(String, Option<String>)> {
    // Remove the leading slash and ".nar" extension
    let path = path.trim_start_matches('/').trim_end_matches(".nar");

    // Check if it's a nix-serve style URL or our style
    if let Some((outhash, narhash)) = path.split_once('-') {
        // nix-serve style: /nar/{outhash}-{narhash}.nar
        if outhash.len() != 32 || narhash.len() != 52 {
            return Err(anyhow!("Invalid NAR path format: {}", path));
        }
        Ok((narhash.to_string(), Some(outhash.to_string())))
    } else {
        // Our style: /nar/{narhash}.nar?hash={outhash}
        if path.len() != 52 {
            return Err(anyhow!("Invalid NAR hash length: {}", path));
        }
        Ok((path.to_string(), None))
    }
}

/// NAR endpoint
pub async fn get(
    path: &str,
    query: Option<&str>,
    _config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("NAR request: {}", path);

    // Parse the path and query
    let (narhash, path_outhash) = parse_nar_path(path)?;

    // Get the output hash, either from the path or the query
    let outhash = if let Some(hash) = path_outhash {
        hash
    } else if let Some(hash) = parse_query(query) {
        hash
    } else {
        debug!("Missing output hash in NAR request");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .header("Cache-Control", "no-store")
            .body(full_body("Missing output hash"))
            .unwrap());
    };

    // Query the path from the hash part
    let store_path = match store.query_path_from_hash_part(&outhash).await? {
        Some(path) => path,
        None => {
            debug!("Store path not found for hash: {}", outhash);
            return Ok(not_found());
        }
    };

    // Get path info
    let path_info = match store.query_path_info(&store_path).await? {
        Some(info) => info,
        None => {
            debug!("Path info not found for: {}", store_path);
            return Ok(not_found());
        }
    };

    // Verify the NAR hash
    let info_hash_nix32 = match convert_base16_to_nix32(&path_info.hash) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to convert hash: {}", e);
            return Ok(internal_error(&format!("Failed to convert hash: {}", e)));
        }
    };

    if narhash != info_hash_nix32 {
        debug!("Hash mismatch: {} != {}", narhash, info_hash_nix32);
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain")
            .header("Cache-Control", "no-store")
            .body(full_body("Hash mismatch detected"))
            .unwrap());
    }

    // Get the real store path
    let real_path = store.get_real_path(&PathBuf::from(&store_path));

    // Stream the NAR
    let nar_stream = match nar::stream_nar(real_path).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to stream NAR: {}", e);
            return Ok(internal_error(&format!("Failed to stream NAR: {}", e)));
        }
    };

    // Transform the stream to ensure it can be used with BoxBody
    // Convert Bytes to Frame<Bytes> as required by hyper 1.0
    let mapped_stream = nar_stream.map(|result| {
        match result {
            Ok(chunk) => Ok(Frame::data(chunk)),
            Err(e) => {
                error!("Error streaming NAR: {}", e);
                Ok(Frame::data(Bytes::new())) // Return empty frame on error
            }
        }
    });

    // Create a BoxBody type explicitly to avoid type mismatch
    let body = BoxBody::new(StreamBody::new(mapped_stream));

    let response = Response::builder()
        .header("Content-Type", "application/x-nix-archive")
        .header("Accept-Ranges", "bytes")
        .header("Cache-Control", "max-age=31536000") // 1 year
        .body(body)
        .unwrap();

    Ok(response)
}
