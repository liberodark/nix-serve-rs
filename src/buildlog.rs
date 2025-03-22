use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::StreamBody;
use hyper::body::Frame;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use tracing::{debug, error};

use crate::config::Config;
use crate::routes::{full_body, not_found};
use crate::store::Store;

/// Get the path to a build log file for a derivation
///
/// Nix stores build logs in /nix/var/log/nix/drvs/{first2}/{rest}
/// This function converts a derivation hash to the corresponding log path
fn get_build_log_path(store_path: &Path, drv_path: &Path) -> Option<PathBuf> {
    let drv_name = drv_path.file_name()?;
    let drv_name = drv_name.to_str()?;

    // Build logs are stored in /nix/var/log/nix/drvs/{first2}/{rest}
    if drv_name.len() < 2 {
        return None;
    }

    let first2 = &drv_name[0..2];
    let rest = &drv_name[2..];

    let store_dir = store_path.parent()?;
    let log_path = store_dir
        .join("var")
        .join("log")
        .join("nix")
        .join("drvs")
        .join(first2)
        .join(rest);

    if log_path.exists() {
        return Some(log_path);
    }

    // Check if a compressed version exists
    let compressed_log = log_path.with_extension("drv.bz2");
    if compressed_log.exists() {
        return Some(compressed_log);
    }

    None
}

/// Determine if a log file is compressed (has .bz2 extension)
fn is_compressed_log(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext == "bz2")
        .unwrap_or(false)
}

/// Handler for the /log/{hash} endpoint
pub async fn get(
    drv: &str,
    config: &Arc<Config>,
    store: &Arc<Store>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Build log request for: {}", drv);

    // Get the derivation path from the hash
    let drv_path = match store
        .daemon
        .lock()
        .await
        .query_path_from_hash_part(drv)
        .await?
    {
        Some(path) => path,
        None => {
            debug!("Derivation path not found for hash: {}", drv);
            return Ok(not_found());
        }
    };

    // Check if the path is valid
    if !store.daemon.lock().await.is_valid_path(&drv_path).await? {
        debug!("Invalid derivation path: {}", drv_path);
        return Ok(not_found());
    }

    // Get the path to the build log
    let store_path = PathBuf::from(store.real_store());
    let drv_path_buf = PathBuf::from(&drv_path);
    let log_path = match get_build_log_path(&store_path, &drv_path_buf) {
        Some(path) => path,
        None => {
            debug!("Build log not found for: {}", drv_path);
            return Ok(not_found());
        }
    };

    // Check if the log is compressed
    let is_compressed = is_compressed_log(&log_path);

    if is_compressed {
        debug!("Serving compressed build log: {}", log_path.display());

        // For bz2 files, use a command to decompress (just like nix-server-ng and harmonia)
        let mut cmd = tokio::process::Command::new("bzip2")
            .arg("-d")
            .arg("-c")
            .arg(&log_path)
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        let stdout = cmd
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stdout of bzip2 process"))?;

        // Create a stream from the decompressed output
        let decompressed_stream = ReaderStream::new(stdout);

        // Transform the stream for hyper 1.0 compatibility
        let mapped_stream = decompressed_stream.map(|result| match result {
            Ok(chunk) => Ok(Frame::data(chunk)),
            Err(e) => {
                error!("Error reading decompressed build log: {}", e);
                Ok(Frame::data(Bytes::new()))
            }
        });

        let body = BoxBody::new(StreamBody::new(mapped_stream));

        Ok(Response::builder()
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Cache-Control", "max-age=31536000") // 1 year
            .body(body)
            .unwrap())
    } else {
        // For uncompressed logs, stream directly from the file
        match File::open(&log_path).await {
            Ok(file) => {
                debug!("Serving uncompressed build log: {}", log_path.display());
                let stream = ReaderStream::new(file);

                // Transform the stream for hyper 1.0 compatibility
                let mapped_stream = stream.map(|result| match result {
                    Ok(chunk) => Ok(Frame::data(chunk)),
                    Err(e) => {
                        error!("Error reading build log: {}", e);
                        Ok(Frame::data(Bytes::new()))
                    }
                });

                let body = BoxBody::new(StreamBody::new(mapped_stream));

                Ok(Response::builder()
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .header("Cache-Control", "max-age=31536000") // 1 year
                    .body(body)
                    .unwrap())
            }
            Err(e) => {
                error!("Failed to open build log {}: {}", log_path.display(), e);
                Ok(not_found())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_build_log_path() {
        let temp_dir = tempdir().unwrap();
        let store_path = temp_dir.path().join("nix").join("store");
        let drv_path = store_path.join("abcdefghijklmnopqrstuvwxyz123456-test.drv");

        // Create the log directory structure
        let log_dir = temp_dir
            .path()
            .join("nix")
            .join("var")
            .join("log")
            .join("nix")
            .join("drvs")
            .join("ab");
        std::fs::create_dir_all(&log_dir).unwrap();

        // Create a test log file
        let log_file = log_dir.join("cdefghijklmnopqrstuvwxyz123456");
        let mut file = std::fs::File::create(&log_file).unwrap();
        writeln!(file, "Test build log content").unwrap();

        // Test finding the log file
        let found_path = get_build_log_path(&store_path, &drv_path);
        assert!(found_path.is_some());
        assert_eq!(found_path.unwrap(), log_file);

        // Test with compressed log
        std::fs::rename(&log_file, &log_file.with_extension("drv.bz2")).unwrap();
        let found_compressed = get_build_log_path(&store_path, &drv_path);
        assert!(found_compressed.is_some());
        assert_eq!(
            found_compressed.unwrap(),
            log_file.with_extension("drv.bz2")
        );

        // Test with non-existent log
        std::fs::remove_file(&log_file.with_extension("drv.bz2")).unwrap();
        let not_found = get_build_log_path(&store_path, &drv_path);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_is_compressed_log() {
        assert!(is_compressed_log(Path::new("path/to/log.drv.bz2")));
        assert!(!is_compressed_log(Path::new("path/to/log.drv")));
        assert!(!is_compressed_log(Path::new("path/to/log")));
    }
}
