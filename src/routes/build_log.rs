use anyhow::Result;
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
use crate::nix::store::NixStore;
use crate::routes::not_found;

/// Get the path to a build log file for a derivation
fn get_build_log_path(store_path: &Path, drv_path: &Path) -> Option<PathBuf> {
    let drv_name = drv_path.file_name()?;
    let drv_name = drv_name.to_str()?;

    // Build logs are stored in /nix/var/log/nix/drvs/{first2}/{rest}
    // where {first2} are the first 2 characters of the hash
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

    let compressed_log = log_path.with_extension("drv.bz2");
    if compressed_log.exists() {
        return Some(compressed_log);
    }

    None
}

pub async fn get(
    drv: &str,
    _config: &Arc<Config>,
    store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Build log request for: {}", drv);

    let drv_path = match store.query_path_from_hash_part(drv).await? {
        Some(path) => path,
        None => {
            debug!("Derivation path not found for hash: {}", drv);
            return Ok(not_found());
        }
    };

    if !store.is_valid_path(&drv_path).await? {
        debug!("Invalid derivation path: {}", drv_path);
        return Ok(not_found());
    }

    let store_path = PathBuf::from(store.real_store());
    let drv_path_buf = PathBuf::from(&drv_path);
    let log_path = match get_build_log_path(&store_path, &drv_path_buf) {
        Some(path) => path,
        None => {
            debug!("Build log not found for: {}", drv_path);
            return Ok(not_found());
        }
    };

    match File::open(&log_path).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);

            // Transform the stream to ensure it can be used with BoxBody
            // Convert Bytes to Frame<Bytes> as required by hyper 1.0
            let mapped_stream = stream.map(|result| {
                match result {
                    Ok(chunk) => Ok(Frame::data(chunk)),
                    Err(e) => {
                        error!("Error reading build log: {}", e);
                        Ok(Frame::data(Bytes::new())) // Return empty frame on error
                    }
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
