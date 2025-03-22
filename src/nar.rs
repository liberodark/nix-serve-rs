use anyhow::{bail, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use http_range::HttpRange;
use hyper::body::Frame;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::Command;
use tracing::{debug, error, info};

use crate::config::Config;
use crate::error::NixServeError;
use crate::routes::{full_body, internal_error, not_found};
use crate::signing::convert_base16_to_nix32;
use crate::store::Store;

/// Represents the query parameters of a NAR URL
#[derive(Debug)]
struct NarQuery {
    hash: Option<String>,
}

/// Parse the query string of a NAR request to extract the hash parameter
fn parse_query(query: Option<&str>) -> Option<String> {
    query.and_then(|q| {
        debug!("Parsing query string: {}", q);
        let pairs = q.split('&').collect::<Vec<_>>();
        for pair in pairs {
            if let Some((key, val)) = pair.split_once('=') {
                if key == "hash" {
                    debug!("Found hash in query: {}", val);
                    return Some(val.to_string());
                }
            }
        }
        None
    })
}

/// Parse the NAR URL path to extract hash and compression information
///
/// Returns a tuple of (narhash, output_hash_option, is_compressed)
fn parse_nar_path(path: &str) -> Result<(String, Option<String>, bool)> {
    // Check if the path is compressed
    let is_compressed = path.ends_with(".nar.xz") || path.ends_with(".nar.zst");
    debug!("Path is compressed: {}", is_compressed);

    // Remove the leading slash and "nar/" prefix
    let base_path = path.trim_start_matches('/').trim_start_matches("nar/");
    debug!("Parsing NAR path: {}", base_path);

    // Extract the filename part without extensions
    let path_without_ext = if path.ends_with(".nar.xz") {
        base_path.trim_end_matches(".nar.xz")
    } else if path.ends_with(".nar.zst") {
        base_path.trim_end_matches(".nar.zst")
    } else {
        base_path.trim_end_matches(".nar")
    };

    // Check if there's a query part and remove it
    let path_without_query = path_without_ext
        .split('?')
        .next()
        .unwrap_or(path_without_ext);
    debug!("Path without query: {}", path_without_query);

    // Check if it's a nix-serve style URL or direct style
    if let Some((outhash, narhash)) = path_without_query.split_once('-') {
        // nix-serve style: /nar/{outhash}-{narhash}.nar(.xz)
        // Allow both 32 and 36 chars for compatibility with different hash formats
        if outhash.len() != 32 && outhash.len() != 36 {
            debug!("Invalid output hash length: {}", outhash.len());
            bail!("Invalid output hash length in path: {}", outhash.len());
        }
        debug!(
            "Parsed as nix-serve style URL: outhash={}, narhash={}",
            outhash, narhash
        );
        Ok((
            narhash.to_string(),
            Some(outhash.to_string()),
            is_compressed,
        ))
    } else {
        // Direct style: /nar/{hash}.nar(.xz) or /nar/{hash}.nar?hash=XXX
        // This is what nix copy uses when uploading
        let hash = path_without_query.to_string();
        debug!("Parsed as direct style URL: hash={}", hash);

        // When there's only one hash in the path, treat it as both narhash and outhash
        // This allows direct uploads from nix copy
        Ok((hash.clone(), Some(hash), is_compressed))
    }
}

/// Handle HTTP HEAD requests for NAR files
/// This checks if a NAR exists without transferring the file data
pub async fn head(
    path: &str,
    query: Option<&str>,
    config: &Arc<Config>,
    store: &Arc<Store>,
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
    let store_path = match store
        .daemon
        .lock()
        .await
        .query_path_from_hash_part(&outhash)
        .await?
    {
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
    let path_info = match store
        .daemon
        .lock()
        .await
        .query_path_info(&store_path)
        .await?
    {
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
    let content_length = if is_compressed && config.compress_nars {
        // We don't know the compressed size without actually compressing,
        // but we can estimate it as roughly 30% of the original size for xz
        // or 40% for zstd
        let ratio = if config.compression_format == "zstd" {
            0.4
        } else {
            0.3
        };
        (path_info.nar_size as f64 * ratio) as u64
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

/// Handle GET requests for NAR files
pub async fn get(
    path: &str,
    query: Option<&str>,
    request_headers: &HeaderMap,
    config: &Arc<Config>,
    store: &Arc<Store>,
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

    debug!("Using output hash: {}", outhash);

    // Query the path from the hash part
    let store_path = match store
        .daemon
        .lock()
        .await
        .query_path_from_hash_part(&outhash)
        .await?
    {
        Some(path) => {
            debug!("Found store path: {}", path);
            path
        }
        None => {
            debug!("Store path not found for hash: {}", outhash);
            return Ok(not_found());
        }
    };

    // Get path info
    let path_info = match store
        .daemon
        .lock()
        .await
        .query_path_info(&store_path)
        .await?
    {
        Some(info) => {
            debug!("Found path info for: {}", store_path);
            info
        }
        None => {
            debug!("Path info not found for: {}", store_path);
            return Ok(not_found());
        }
    };

    // Verify the NAR hash - we now do this in a separate step if needed
    // We'll check when the actual request is not for a compressed file
    if !is_compressed {
        debug!("Raw hash from path info: {}", path_info.hash);
        let info_hash_nix32 = match convert_base16_to_nix32(&path_info.hash) {
            Ok(hash) => {
                debug!("Converted hash to base32: {}", hash);
                hash
            }
            Err(e) => {
                error!("Failed to convert hash: {}", e);
                return Ok(internal_error(&format!("Failed to convert hash: {}", e)));
            }
        };

        // Only verify hash if this is a direct NAR request without compression
        if path.ends_with(".nar") && !path.contains(&info_hash_nix32) {
            debug!(
                "Hash mismatch: expected {}, path does not contain it",
                info_hash_nix32
            );
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "text/plain")
                .header("Cache-Control", "no-store")
                .body(full_body("Hash mismatch detected"))
                .unwrap());
        }
    }

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

    // Regular request - stream full NAR
    if let Some(range) = range_header {
        handle_range_request(range, path_info.nar_size, store_path, is_compressed).await
    } else if should_compress {
        handle_compressed_nar(&store_path, config, path_info.nar_size).await
    } else {
        handle_uncompressed_nar(store, &store_path, content_type, path_info.nar_size).await
    }
}

/// Handle HTTP range requests for NAR files
async fn handle_range_request(
    range_header: &str,
    nar_size: u64,
    store_path: String,
    is_compressed: bool,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    // Parse range header
    let ranges = match HttpRange::parse(range_header, nar_size) {
        Ok(ranges) => ranges,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{}", nar_size))
                .body(full_body("Invalid range format"))
                .unwrap());
        }
    };

    if ranges.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header("Content-Range", format!("bytes */{}", nar_size))
            .body(full_body("No valid ranges specified"))
            .unwrap());
    }

    // Currently we only support a single range
    let range = ranges[0];

    // Calculate the end value from start and length
    let start = range.start;
    // Ensure end doesn't exceed file size
    let end = std::cmp::min(range.start + range.length - 1, nar_size - 1);

    if start > end || start >= nar_size {
        return Ok(Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header("Content-Range", format!("bytes */{}", nar_size))
            .body(full_body("Invalid range values"))
            .unwrap());
    }

    // For ranged requests with NAR, we need to create a temporary NAR file
    // and then serve a range from it
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("temp.nar");

    // Dump the NAR to a temp file
    let dump_status = Command::new("nix-store")
        .arg("--dump")
        .arg(&store_path)
        .arg("--to-file")
        .arg(&temp_path)
        .status()
        .await?;

    if !dump_status.success() {
        return Ok(internal_error("Failed to create temporary NAR file"));
    }

    // Open the file
    let file = tokio::fs::File::open(&temp_path).await?;
    let file_size = file.metadata().await?.len();

    // Create a reader that seeks to the start position
    let mut reader = tokio::io::BufReader::new(file);
    tokio::io::AsyncSeekExt::seek(&mut reader, std::io::SeekFrom::Start(start)).await?;

    // Take only the range length
    let range_reader = reader.take(end - start + 1);
    let stream = tokio_util::io::ReaderStream::new(range_reader);

    // Map the stream for hyper
    let mapped_stream = stream.map(|result| match result {
        Ok(chunk) => Ok(Frame::data(chunk)),
        Err(e) => {
            error!("Error streaming NAR: {}", e);
            Ok(Frame::data(Bytes::new()))
        }
    });

    let body = BoxBody::new(StreamBody::new(mapped_stream));

    let content_type = if is_compressed {
        "application/x-nix-archive-compressed"
    } else {
        "application/x-nix-archive"
    };

    Ok(Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header("Content-Type", content_type)
        .header("Accept-Ranges", "bytes")
        .header("Content-Length", (end - start + 1).to_string())
        .header(
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, file_size),
        )
        .header("Cache-Control", "max-age=31536000") // 1 year
        .body(body)
        .unwrap())
}

/// Handle compressed NAR file delivery
async fn handle_compressed_nar(
    store_path: &str,
    config: &Arc<Config>,
    nar_size: u64,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Handling compressed NAR request for {}", store_path);

    // For compressed NARs, we handle this by dumping to a file and then compressing
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("temp.nar");

    // First dump the NAR to a temp file
    let output = Command::new("nix-store")
        .arg("--dump")
        .arg(store_path)
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

    // Then compress it with xz or zstd
    let compression_cmd = if config.compression_format == "zstd" {
        "zstd"
    } else {
        "xz"
    };

    let level_arg = format!("-{}", config.compression_level);

    let compress_output = Command::new(compression_cmd)
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

    // Write compressed data to a new temporary file
    let compressed_path = temp_dir.path().join(format!(
        "temp.nar.{}",
        if config.compression_format == "zstd" {
            "zst"
        } else {
            "xz"
        }
    ));

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
}

/// Handle uncompressed NAR file delivery by streaming directly from the daemon
async fn handle_uncompressed_nar(
    store: &Arc<Store>,
    store_path: &str,
    content_type: &str,
    nar_size: u64,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Streaming uncompressed NAR for {}", store_path);

    // We'll use a channel to stream the NAR data
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(100);

    let store_path_clone = store_path.to_string();
    let store_clone = Arc::clone(store);

    // Spawn a task to stream the NAR from the daemon
    tokio::spawn(async move {
        // We create an adapter to transform the Bytes into http::Frame
        let callback = |chunk: Vec<u8>| {
            let bytes = Bytes::from(chunk);
            tx.try_send(Ok(bytes))
                .map_err(|e| anyhow::anyhow!("Failed to send NAR chunk: {}", e))
        };

        if let Err(e) = store_clone
            .daemon
            .lock()
            .await
            .stream_nar(&store_path_clone, callback)
            .await
        {
            error!("Error streaming NAR from daemon: {}", e);
        }
    });

    // Convert the receiver into a stream
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = BoxBody::new(StreamBody::new(stream));

    Ok(Response::builder()
        .header("Content-Type", content_type)
        .header("Accept-Ranges", "bytes")
        .header("Content-Length", nar_size.to_string())
        .header("Cache-Control", "max-age=31536000") // 1 year
        .body(body)
        .unwrap())
}

/// Handle PUT requests for NAR files (uploads)
pub async fn put(
    path: &str,
    body: Bytes,
    config: &Arc<Config>,
    store: &Arc<Store>,
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
        processed_body = decompress_nar_data(
            body,
            if path.ends_with(".nar.zst") {
                "zstd"
            } else {
                "xz"
            },
        )
        .await?;
    } else {
        // No decompression needed
        processed_body = body;
    }

    // Create a temporary file to store the NAR
    let temp_dir = tempfile::tempdir()?;
    let nar_path = temp_dir.path().join("temp.nar");

    // Write the NAR data to the temporary file
    tokio::fs::write(&nar_path, &processed_body).await?;

    // Import the NAR into the Nix store
    let output = Command::new("nix-store")
        .arg("--import")
        .arg(&nar_path)
        .output()
        .await?;

    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        error!("Failed to import NAR: {}", error_msg);
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "text/plain")
            .body(full_body(&format!("Failed to import NAR: {}", error_msg)))
            .unwrap());
    }

    let store_path = String::from_utf8(output.stdout)
        .context("Failed to parse nix-store output")?
        .trim()
        .to_string();

    info!("Imported NAR to store path: {}", store_path);

    // Create narinfo file
    let create_narinfo = match create_narinfo_for_path(&store_path, &hash_part, config).await {
        Ok(()) => true,
        Err(e) => {
            error!("Failed to create narinfo: {}", e);
            false
        }
    };

    // Return success
    let status_message = if create_narinfo {
        format!("Successfully imported NAR to {}", store_path)
    } else {
        format!(
            "Imported NAR to {} but failed to create narinfo",
            store_path
        )
    };

    info!("Successfully processed NAR upload: {}", path);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(full_body(&status_message))
        .unwrap())
}

/// Helper function to create a narinfo file for a store path
async fn create_narinfo_for_path(
    store_path: &str,
    hash_part: &str,
    config: &Arc<Config>,
) -> Result<()> {
    // Extract basename from the store path (e.g., "abcdef-foo" from "/nix/store/abcdef-foo")
    let basename = store_path
        .split('/')
        .last()
        .ok_or_else(|| anyhow::anyhow!("Invalid store path"))?;

    // Get path info
    let cmd = Command::new("nix-store")
        .arg("--query")
        .arg("--references")
        .arg(store_path)
        .output()
        .await?;

    if !cmd.status.success() {
        bail!(
            "Failed to query references: {}",
            String::from_utf8_lossy(&cmd.stderr)
        );
    }

    let refs = String::from_utf8(cmd.stdout)?
        .lines()
        .filter_map(|r| r.split('/').last().map(|s| s.to_string()))
        .collect::<Vec<_>>()
        .join(" ");

    // Get NAR size and hash
    let size_cmd = Command::new("nix-store")
        .arg("--query")
        .arg("--size")
        .arg(store_path)
        .output()
        .await?;

    if !size_cmd.status.success() {
        bail!(
            "Failed to query size: {}",
            String::from_utf8_lossy(&size_cmd.stderr)
        );
    }

    let nar_size = String::from_utf8(size_cmd.stdout)?.trim().parse::<u64>()?;

    let hash_cmd = Command::new("nix-store")
        .arg("--query")
        .arg("--hash")
        .arg(store_path)
        .output()
        .await?;

    if !hash_cmd.status.success() {
        bail!(
            "Failed to query hash: {}",
            String::from_utf8_lossy(&hash_cmd.stderr)
        );
    }

    let raw_hash = String::from_utf8(hash_cmd.stdout)?.trim().to_string();

    // Convert to base32 if needed
    let nar_hash = if raw_hash.starts_with("sha256:") {
        raw_hash
    } else {
        format!("sha256:{}", convert_base16_to_nix32(&raw_hash)?)
    };

    // Create the narinfo content
    let narinfo_content = format!(
        "StorePath: {}\nURL: nar/{}.nar\nCompression: none\nNarHash: {}\nNarSize: {}\nReferences: {}\n",
        store_path,
        hash_part,
        nar_hash,
        nar_size,
        refs
    );

    // Determine the directory to store narinfo files
    let narinfo_dir = PathBuf::from(config.real_store())
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Can't determine parent of store directory"))?
        .to_path_buf();

    // Write narinfo file
    let narinfo_path = narinfo_dir.join(format!("{}.narinfo", hash_part));
    tokio::fs::write(&narinfo_path, narinfo_content).await?;

    info!("Created narinfo file at: {}", narinfo_path.display());
    Ok(())
}

/// Decompress NAR data from xz or zstd format
async fn decompress_nar_data(body: Bytes, format: &str) -> Result<Bytes> {
    // Create a temp directory
    let temp_dir = tempfile::tempdir()?;
    let compressed_path = temp_dir.path().join("input.nar.compressed");

    // Write the compressed data to a file
    tokio::fs::write(&compressed_path, &body).await?;

    // Choose decompression command based on format
    let (cmd, args) = match format {
        "xz" => ("xz", vec!["-d", "-c"]),
        "zstd" => ("zstd", vec!["-d", "-c"]),
        _ => {
            bail!("Unsupported compression format: {}", format)
        }
    };

    // Run decompression command
    let output = Command::new(cmd)
        .args(args)
        .arg(&compressed_path)
        .output()
        .await
        .context(format!("Failed to run {} decompression", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Decompression failed: {}", stderr);
    }

    Ok(Bytes::from(output.stdout))
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
    fn test_parse_nar_path_compressed_xz() {
        let path = "/nar/abcdef1234567890.nar.xz";
        let (narhash, outhash, is_compressed) = parse_nar_path(path).unwrap();
        assert_eq!(narhash, "abcdef1234567890");
        assert_eq!(outhash.unwrap(), "abcdef1234567890");
        assert_eq!(is_compressed, true);
    }

    #[test]
    fn test_parse_nar_path_compressed_zstd() {
        let path = "/nar/abcdef1234567890.nar.zst";
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
    fn test_parse_nar_path_with_query() {
        let path = "/nar/abcdef1234567890.nar?hash=00000000000000000000000000000000";
        let (narhash, outhash, is_compressed) = parse_nar_path(path).unwrap();
        assert_eq!(narhash, "abcdef1234567890");
        assert_eq!(outhash.unwrap(), "abcdef1234567890");
        assert_eq!(is_compressed, false);
    }

    #[test]
    fn test_parse_query() {
        let query = "hash=00000000000000000000000000000000&other=value";
        let result = parse_query(Some(query));
        assert_eq!(result, Some("00000000000000000000000000000000".to_string()));
    }
}
