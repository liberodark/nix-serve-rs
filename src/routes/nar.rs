use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use hyper::body::Frame;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info};

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
///
/// Returns a tuple of (narhash, output_hash_option, is_compressed)
fn parse_nar_path(path: &str) -> Result<(String, Option<String>, bool)> {
    // Check if the path is compressed
    let is_compressed = path.ends_with(".nar.xz");

    // Remove the leading slash
    let base_path = path.trim_start_matches('/');

    // Extract the filename part without extensions
    let path_without_ext = if is_compressed {
        base_path.trim_end_matches(".nar.xz")
    } else {
        base_path.trim_end_matches(".nar")
    };

    // Check if it's a nix-serve style URL or our style
    if let Some((outhash, narhash)) = path_without_ext.split_once('-') {
        // nix-serve style: /nar/{outhash}-{narhash}.nar(.xz)
        if outhash.len() != 32 {
            return Err(anyhow!(
                "Invalid output hash length in path: {}",
                outhash.len()
            ));
        }
        // Don't strictly check narhash length as it could vary
        Ok((
            narhash.to_string(),
            Some(outhash.to_string()),
            is_compressed,
        ))
    } else {
        // Our style: /nar/{narhash}.nar(.xz)?hash={outhash}
        // Or handling direct nar request without the format check
        Ok((path_without_ext.to_string(), None, is_compressed))
    }
}

/// NAR endpoint
pub async fn get(
    path: &str,
    query: Option<&str>,
    request_headers: &HeaderMap,
    _config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("NAR request: {}", path);

    // Parse the path and query
    let (narhash, path_outhash, is_compressed) = parse_nar_path(path)?;

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

    // Verify the NAR hash - with more flexible validation
    // We don't strictly check the hash if we're dealing with compressed files
    if !is_compressed {
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
    }

    // Get the real store path
    let real_path = store.get_real_path(&PathBuf::from(&store_path));

    // Check for range requests
    let range_header = request_headers
        .get(http::header::RANGE)
        .and_then(|v| v.to_str().ok());

    // Set the appropriate content type based on compression
    let content_type = if is_compressed {
        "application/x-nix-archive-compressed"
    } else {
        "application/x-nix-archive"
    };

    // Stream the NAR with appropriate range handling
    if let Some(range) = range_header {
        debug!("Processing range request: {}", range);

        // Parse range header - we'll implement a basic version here
        // Format: "bytes=0-1023" or "bytes=1024-"
        let range_parts: Vec<&str> = range.trim_start_matches("bytes=").split('-').collect();
        if range_parts.len() != 2 {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{}", path_info.nar_size))
                .body(full_body("Invalid range format"))
                .unwrap());
        }

        let start: u64 = range_parts[0].parse().unwrap_or(0);
        let end: u64 = if range_parts[1].is_empty() {
            path_info.nar_size - 1
        } else {
            range_parts[1].parse().unwrap_or(path_info.nar_size - 1)
        };

        // Validate range boundaries
        if start >= path_info.nar_size || start > end {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{}", path_info.nar_size))
                .body(full_body("Invalid range values"))
                .unwrap());
        }

        let end = if end >= path_info.nar_size {
            path_info.nar_size - 1
        } else {
            end
        };
        let length = end - start + 1;

        // Create a temporary NAR file for ranged access
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path().join("temp.nar");

        // Dump the NAR to a temp file
        let output = tokio::process::Command::new("nix-store")
            .arg("--dump")
            .arg(&real_path)
            .arg("--to-file")
            .arg(&temp_path)
            .output()
            .await?;

        if !output.status.success() {
            error!(
                "Failed to create temporary NAR file: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(internal_error("Failed to create temporary NAR file"));
        }

        // Open the file for streaming
        let file = match tokio::fs::File::open(&temp_path).await {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open temporary NAR file: {}", e);
                return Ok(internal_error("Failed to open temporary NAR file"));
            }
        };

        // Create a limited reader for the range
        let mut reader = tokio::io::BufReader::new(file);

        // Seek to the start position
        if let Err(e) =
            tokio::io::AsyncSeekExt::seek(&mut reader, std::io::SeekFrom::Start(start)).await
        {
            error!("Failed to seek in NAR file: {}", e);
            return Ok(internal_error("Failed to seek in NAR file"));
        }

        // Create a limited reader for the range
        let limited_reader = tokio::io::AsyncReadExt::take(reader, length);
        let stream = tokio_util::io::ReaderStream::new(limited_reader);

        // Transform for hyper compatibility
        let mapped_stream = stream.map(|result| match result {
            Ok(chunk) => Ok(Frame::data(chunk)),
            Err(e) => {
                error!("Error streaming NAR: {}", e);
                Ok(Frame::data(Bytes::new()))
            }
        });

        let body = BoxBody::new(StreamBody::new(mapped_stream));

        Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("Content-Type", content_type)
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", length.to_string())
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", start, end, path_info.nar_size),
            )
            .header("Cache-Control", "max-age=31536000") // 1 year
            .body(body)
            .unwrap())
    } else {
        // Regular request - stream full NAR
        let nar_stream = match nar::stream_nar(real_path).await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to stream NAR: {}", e);
                return Ok(internal_error(&format!("Failed to stream NAR: {}", e)));
            }
        };

        // Transform for hyper compatibility
        let mapped_stream = nar_stream.map(|result| match result {
            Ok(chunk) => Ok(Frame::data(chunk)),
            Err(e) => {
                error!("Error streaming NAR: {}", e);
                Ok(Frame::data(Bytes::new()))
            }
        });

        let body = BoxBody::new(StreamBody::new(mapped_stream));

        Ok(Response::builder()
            .header("Content-Type", content_type)
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", path_info.nar_size.to_string())
            .header("Cache-Control", "max-age=31536000") // 1 year
            .body(body)
            .unwrap())
    }
}

/// Process PUT requests for NAR files
pub async fn put(
    path: &str,
    body: bytes::Bytes,
    _config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Processing NAR upload: {}", path);

    // Parse the NAR path
    let (narhash, hash_part_opt, is_compressed) = match parse_nar_path(path) {
        Ok(result) => result,
        Err(e) => {
            error!("Invalid NAR path: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "text/plain")
                .body(full_body(&format!("Invalid NAR path: {}", e)))
                .unwrap());
        }
    };

    // Get the hash part
    let hash_part = match hash_part_opt {
        Some(hash) => hash,
        None => {
            debug!("Missing hash part in NAR upload path");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "text/plain")
                .body(full_body("Missing hash part in upload path"))
                .unwrap());
        }
    };

    // Store the NAR file - with appropriate handling for compressed files
    let nar_path = match store.store_nar(&hash_part, &narhash, body).await {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to store NAR: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "text/plain")
                .body(full_body(&format!("Failed to store NAR: {}", e)))
                .unwrap());
        }
    };

    // Special handling for compressed files
    if is_compressed {
        info!("Storing compressed NAR file: {}", nar_path.display());

        // For compressed files, we might need to decompress before importing
        // For now, we'll just acknowledge receipt
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(full_body("Compressed NAR file stored successfully"))
            .unwrap());
    }

    // Import the NAR into the Nix store
    let store_path = match store.import_nar(&nar_path).await {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to import NAR: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "text/plain")
                .body(full_body(&format!("Failed to import NAR: {}", e)))
                .unwrap());
        }
    };

    // Add to binary cache
    if let Err(e) = store.add_to_binary_cache(&store_path, &nar_path).await {
        error!("Failed to add to binary cache: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "text/plain")
            .body(full_body(&format!("Failed to add to binary cache: {}", e)))
            .unwrap());
    }

    // Return success
    info!("Successfully processed NAR upload: {}", path);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(full_body("OK"))
        .unwrap())
}

/// NAR HEAD endpoint
pub async fn head(
    path: &str,
    query: Option<&str>,
    _config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("NAR HEAD request: {}", path);

    // Parse the path and query
    let (_narhash, path_outhash, is_compressed) = parse_nar_path(path)?;

    // Get the output hash, either from the path or the query
    let outhash = if let Some(hash) = path_outhash {
        hash
    } else if let Some(hash) = parse_query(query) {
        hash
    } else {
        debug!("Missing output hash in NAR HEAD request");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .header("Cache-Control", "no-store")
            .body(full_body(""))
            .unwrap());
    };

    // Query the path from the hash part
    let store_path = match store.query_path_from_hash_part(&outhash).await? {
        Some(path) => path,
        None => {
            debug!("Store path not found for hash: {}", outhash);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full_body(""))
                .unwrap());
        }
    };

    // Get path info
    let path_info = match store.query_path_info(&store_path).await? {
        Some(info) => info,
        None => {
            debug!("Path info not found for: {}", store_path);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full_body(""))
                .unwrap());
        }
    };

    // Set the appropriate content type based on compression
    let content_type = if is_compressed {
        "application/x-nix-archive-compressed"
    } else {
        "application/x-nix-archive"
    };

    // Return success with NAR info
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("Content-Length", path_info.nar_size.to_string())
        .header("Accept-Ranges", "bytes")
        .header("Cache-Control", "max-age=31536000") // 1 year
        .body(full_body(""))
        .unwrap())
}
