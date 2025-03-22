use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use http_range::HttpRange;
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

/// Represents the query string of a NAR URL.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct NarRequest {
    hash: Option<String>,
    outhash: Option<String>,
}

/// Represents the parsed parts in a NAR URL.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct PathParams {
    narhash: String,
    outhash: Option<String>,
}

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

    // Remove the leading slash and "nar/" prefix
    let base_path = path.trim_start_matches('/').trim_start_matches("nar/");

    // Extract the filename part without extensions
    let path_without_ext = if is_compressed {
        base_path.trim_end_matches(".nar.xz")
    } else {
        base_path.trim_end_matches(".nar")
    };

    // Check if it's a nix-serve style URL or our style
    if let Some((outhash, narhash)) = path_without_ext.split_once('-') {
        // nix-serve style: /nar/{outhash}-{narhash}.nar(.xz)
        // Allow both 32 and 36 chars for compatibility with different hash formats
        if outhash.len() != 32 && outhash.len() != 36 {
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
        // Direct style: /nar/{hash}.nar(.xz)
        // This is what nix copy uses when uploading
        let hash = path_without_ext.to_string();

        // When there's only one hash in the path, treat it as both narhash and outhash
        // This allows direct uploads from nix copy
        Ok((hash.clone(), Some(hash), is_compressed))
    }
}

/// NAR endpoint
pub async fn get(
    path: &str,
    query: Option<&str>,
    request_headers: &HeaderMap,
    config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("NAR request: {}", path);

    // Parse the path and query
    let (_narhash, path_outhash, is_compressed) = parse_nar_path(path)?;

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

    // Verify the NAR hash - we now do this in a separate step if needed
    // We'll check when the actual request is not for a compressed file
    if !is_compressed {
        let info_hash_nix32 = match convert_base16_to_nix32(&path_info.hash) {
            Ok(hash) => hash,
            Err(e) => {
                error!("Failed to convert hash: {}", e);
                return Ok(internal_error(&format!("Failed to convert hash: {}", e)));
            }
        };

        // Only verify hash if this is a direct NAR request without compression
        if path.ends_with(".nar") && !path.contains(&info_hash_nix32) {
            debug!("Hash mismatch: expected {}", info_hash_nix32);
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

    // Determine if we need to compress the response
    let should_compress = is_compressed && config.compress_nars;

    // Stream the NAR with appropriate range handling
    if let Some(range) = range_header {
        debug!("Processing range request: {}", range);

        // Parse range header
        let ranges = match HttpRange::parse(range, path_info.nar_size) {
            Ok(ranges) => ranges,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header("Content-Range", format!("bytes */{}", path_info.nar_size))
                    .body(full_body("Invalid range format"))
                    .unwrap());
            }
        };

        if ranges.is_empty() {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{}", path_info.nar_size))
                .body(full_body("No valid ranges specified"))
                .unwrap());
        }

        // Currently we only support a single range
        let range = ranges[0];

        // Calculate the end value from start and length
        let start = range.start;
        // Ensure end doesn't exceed file size
        let end = std::cmp::min(range.start + range.length - 1, path_info.nar_size - 1);

        if start > end || start >= path_info.nar_size {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{}", path_info.nar_size))
                .body(full_body("Invalid range values"))
                .unwrap());
        }

        let length = end - start + 1;

        // For ranged requests, we use a temp file approach for better reliability
        let (stream, actual_start, actual_end) = match nar::stream_nar_with_range(
            real_path.clone(),
            Some(range_header.unwrap()),
            path_info.nar_size,
        )
        .await
        {
            Ok((stream, actual_start, actual_end)) => (stream, actual_start, actual_end),
            Err(e) => {
                error!("Failed to stream NAR with range: {}", e);
                return Ok(internal_error(&format!(
                    "Failed to stream NAR with range: {}",
                    e
                )));
            }
        };

        // Transform the stream for hyper compatibility
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
                format!(
                    "bytes {}-{}/{}",
                    actual_start, actual_end, path_info.nar_size
                ),
            )
            .header("Cache-Control", "max-age=31536000") // 1 year
            .body(body)
            .unwrap())
    } else {
        // Regular request - stream full NAR

        // If we need compression and it's requested as .nar.xz
        if should_compress {
            // For compressed NARs, we'll handle this by first dumping to a file and then compressing
            let temp_dir = tempfile::tempdir()?;
            let temp_path = temp_dir.path().join("temp.nar");

            // First dump the NAR to a temp file
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

            // Then compress it with xz using standard process (avoiding tokio::fs::File issues)
            let compressed_path = temp_dir.path().join("temp.nar.xz");
            let level_arg = format!("-{}", config.compression_level);

            let compress_output = tokio::process::Command::new("xz")
                .arg("-z")
                .arg(level_arg)
                .arg("-c")
                .arg(&temp_path)
                .output()
                .await?;

            if !compress_output.status.success() {
                error!("Failed to compress NAR file");
                return Ok(internal_error("Failed to compress NAR file"));
            }

            // Write compressed data to file
            tokio::fs::write(&compressed_path, &compress_output.stdout).await?;

            // Get the compressed file size
            let compressed_size = tokio::fs::metadata(&compressed_path).await?.len();

            // Stream the compressed file
            let file = tokio::fs::File::open(&compressed_path).await?;
            let reader = tokio::io::BufReader::new(file);
            let stream = tokio_util::io::ReaderStream::new(reader);

            // Transform for hyper compatibility
            let mapped_stream = stream.map(|result| match result {
                Ok(chunk) => Ok(Frame::data(chunk)),
                Err(e) => {
                    error!("Error streaming compressed NAR: {}", e);
                    Ok(Frame::data(Bytes::new()))
                }
            });

            let body = BoxBody::new(StreamBody::new(mapped_stream));

            Ok(Response::builder()
                .header("Content-Type", "application/x-nix-archive-compressed")
                .header("Accept-Ranges", "bytes")
                .header("Content-Length", compressed_size.to_string())
                .header("Cache-Control", "max-age=31536000") // 1 year
                .body(body)
                .unwrap())
        } else {
            // Regular uncompressed streaming
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
            // If no hash part is provided in the path, use the NAR hash as the hash part
            // This is a fallback for direct uploads
            debug!("No explicit hash part in NAR upload path, using NAR hash");
            narhash.clone()
        }
    };

    let processed_body: Bytes;

    // Handle compressed files - decompress them first
    if is_compressed {
        info!("Decompressing uploaded NAR file for: {}", path);

        // Create a temp directory
        let temp_dir = tempfile::tempdir()?;
        let compressed_path = temp_dir.path().join("input.nar.xz");

        // Write the compressed data to a file
        tokio::fs::write(&compressed_path, &body).await?;

        // Decompress with xz using subprocess instead of piping
        let output = tokio::process::Command::new("xz")
            .arg("-d")
            .arg("-c")
            .arg(&compressed_path)
            .output()
            .await?;

        if !output.status.success() {
            error!("Failed to decompress NAR file");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "text/plain")
                .body(full_body("Failed to decompress NAR file"))
                .unwrap());
        }

        // Use the decompressed output
        processed_body = Bytes::from(output.stdout);
    } else {
        // No decompression needed
        processed_body = body;
    }

    // Store the NAR file
    let nar_path = match store.store_nar(&hash_part, &narhash, processed_body).await {
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

    // If we're supposed to be compressing and this is a compressed request,
    // we should return the expected file size instead of the actual NAR size
    let content_length = if is_compressed {
        // We don't know the compressed size without actually compressing,
        // but we can estimate it as roughly 30% of the original size
        (path_info.nar_size as f64 * 0.3) as u64
    } else {
        path_info.nar_size
    };

    // Return success with NAR info
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("Content-Length", content_length.to_string())
        .header("Accept-Ranges", "bytes")
        .header("Cache-Control", "max-age=31536000") // 1 year
        .body(full_body(""))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nar_path_simple() {
        let path = "/nar/abcdef1234567890.nar";
        let (narhash, outhash, is_compressed) = parse_nar_path(path).unwrap();
        assert_eq!(narhash, "abcdef1234567890");
        assert_eq!(outhash.unwrap(), "abcdef1234567890");
        assert_eq!(is_compressed, false);
    }

    #[test]
    fn test_parse_nar_path_compressed() {
        let path = "/nar/abcdef1234567890.nar.xz";
        let (narhash, outhash, is_compressed) = parse_nar_path(path).unwrap();
        assert_eq!(narhash, "abcdef1234567890");
        assert_eq!(outhash.unwrap(), "abcdef1234567890");
        assert_eq!(is_compressed, true);
    }

    #[test]
    fn test_parse_nar_path_with_separate_hashes() {
        let path = "/nar/00000000000000000000000000000000-abcdef1234567890.nar";
        let (narhash, outhash, is_compressed) = parse_nar_path(path).unwrap();
        assert_eq!(narhash, "abcdef1234567890");
        assert_eq!(outhash.unwrap(), "00000000000000000000000000000000");
        assert_eq!(is_compressed, false);
    }

    #[test]
    fn test_parse_nar_path_with_separate_hashes_compressed() {
        let path = "/nar/00000000000000000000000000000000-abcdef1234567890.nar.xz";
        let (narhash, outhash, is_compressed) = parse_nar_path(path).unwrap();
        assert_eq!(narhash, "abcdef1234567890");
        assert_eq!(outhash.unwrap(), "00000000000000000000000000000000");
        assert_eq!(is_compressed, true);
    }

    #[test]
    fn test_parse_nar_path_nix_copy_format() {
        // Format utilisé par nix copy
        let path = "/nar/08242al70hn299yh1vk6il2cyahh6p86qvm72rmqz1z07q36vsk2.nar.xz";
        let (narhash, outhash, is_compressed) = parse_nar_path(path).unwrap();
        assert_eq!(
            narhash,
            "08242al70hn299yh1vk6il2cyahh6p86qvm72rmqz1z07q36vsk2"
        );
        assert_eq!(
            outhash.unwrap(),
            "08242al70hn299yh1vk6il2cyahh6p86qvm72rmqz1z07q36vsk2"
        );
        assert_eq!(is_compressed, true);
    }
}
