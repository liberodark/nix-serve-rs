use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::error::{NixServeError, NixServeResult};
use crate::nix::daemon::NixDaemon;
use crate::nix::path_info::PathInfo;

pub struct NixStore {
    virtual_store: String,
    real_store: String,
    daemon: Arc<Mutex<NixDaemon>>,
}

impl NixStore {
    pub fn new(virtual_store: &str, real_store: Option<&str>) -> Result<Self> {
        info!("Initializing Nix store: virtual={}", virtual_store);
        if let Some(real) = real_store {
            info!("Using real Nix store: {}", real);
        }

        let daemon = NixDaemon::new()?;

        Ok(Self {
            virtual_store: virtual_store.to_string(),
            real_store: real_store.unwrap_or(virtual_store).to_string(),
            daemon: Arc::new(Mutex::new(daemon)),
        })
    }

    pub fn virtual_store(&self) -> &str {
        &self.virtual_store
    }

    pub fn real_store(&self) -> &str {
        &self.real_store
    }

    pub fn get_real_path(&self, path: &Path) -> PathBuf {
        let path_str = path.to_string_lossy();

        if path_str.starts_with(&self.virtual_store) && self.virtual_store != self.real_store {
            let rel_path = path.strip_prefix(&self.virtual_store).unwrap_or(path);
            Path::new(&self.real_store).join(rel_path)
        } else {
            path.to_path_buf()
        }
    }

    pub async fn is_valid_path(&self, path: &str) -> NixServeResult<bool> {
        let mut daemon = self.daemon.lock().await;
        daemon
            .is_valid_path(path)
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to check path validity: {}", e)))
    }

    pub async fn query_path_from_hash_part(
        &self,
        hash_part: &str,
    ) -> NixServeResult<Option<String>> {
        debug!("Looking up path for hash part: {}", hash_part);
        let mut daemon = self.daemon.lock().await;
        daemon
            .query_path_from_hash_part(hash_part)
            .await
            .map_err(|e| {
                NixServeError::nix_daemon(format!("Failed to query path from hash part: {}", e))
            })
    }

    pub async fn query_path_info(&self, path: &str) -> NixServeResult<Option<PathInfo>> {
        let mut daemon = self.daemon.lock().await;
        daemon
            .query_path_info(path)
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to query path info: {}", e)))
    }

    pub async fn dump_path<F, Fut>(&self, _path: &str, _callback: F) -> NixServeResult<()>
    where
        F: FnMut(bytes::Bytes) -> Fut,
        Fut: std::future::Future<Output = NixServeResult<()>>,
    {
        // We'll use nix-store --dump as an external command rather than
        // using the C++ API directly

        // TODO: Implement using tokio::process to spawn nix-store --dump

        // For now, this is a placeholder that always fails
        Err(NixServeError::internal("dump_path not yet implemented"))
    }
}
