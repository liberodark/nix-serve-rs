use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::daemon::DaemonConnection;
use crate::error::{NixServeError, NixServeResult};

/// Manages access to the Nix store, handling virtual and real paths
#[derive(Debug, Clone, Default)]
pub struct Store {
    /// Virtual store path (as seen by clients)
    virtual_store: String,

    /// Real store path (where files are actually located)
    real_store: Option<String>,

    /// Connection to the Nix daemon
    pub daemon: Arc<Mutex<DaemonConnection>>,
}

impl Store {
    /// Create a new Store instance
    pub fn new(virtual_store: String, real_store: Option<String>) -> Self {
        info!("Initializing Nix store: virtual={}", virtual_store);

        if let Some(real) = &real_store {
            info!("Using real Nix store: {}", real);
        }

        Self {
            virtual_store,
            real_store,
            daemon: Arc::new(Mutex::new(DaemonConnection::default())),
        }
    }

    /// Get the virtual store path
    pub fn virtual_store(&self) -> &str {
        &self.virtual_store
    }

    /// Get the real store path
    pub fn real_store(&self) -> &Path {
        if let Some(ref real) = self.real_store {
            Path::new(real)
        } else {
            Path::new(&self.virtual_store)
        }
    }

    /// Convert a virtual path to a real path
    ///
    /// If the store is using a real path different from the virtual path,
    /// this translates the path to its real location.
    pub fn get_real_path(&self, virtual_path: &Path) -> PathBuf {
        let virtual_str = virtual_path.to_string_lossy();

        if self.real_store.is_some() && virtual_str.starts_with(&self.virtual_store) {
            // Replace virtual store prefix with real store prefix
            let relative_path = match virtual_path.strip_prefix(&self.virtual_store) {
                Ok(rel_path) => rel_path,
                Err(_) => {
                    debug!("Failed to strip prefix from {}", virtual_str);
                    return virtual_path.to_path_buf();
                }
            };

            Path::new(self.real_store()).join(relative_path)
        } else {
            virtual_path.to_path_buf()
        }
    }

    /// Check if a path exists in the Nix store
    pub async fn is_valid_path(&self, path: &str) -> NixServeResult<bool> {
        debug!("Checking if path is valid: {}", path);

        self.daemon
            .lock()
            .await
            .is_valid_path(path)
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to check path validity: {}", e)))
    }

    /// Query a path from a hash part
    pub async fn query_path_from_hash_part(
        &self,
        hash_part: &str,
    ) -> NixServeResult<Option<String>> {
        debug!("Looking up path for hash part: {}", hash_part);

        match self
            .daemon
            .lock()
            .await
            .query_path_from_hash_part(hash_part)
            .await
        {
            Ok(path) => Ok(path),
            Err(e) => Err(NixServeError::nix_daemon(format!(
                "Failed to query path from hash part: {}",
                e
            ))),
        }
    }

    /// Query information about a path
    pub async fn query_path_info(
        &self,
        path: &str,
    ) -> NixServeResult<Option<crate::daemon::ValidPathInfo>> {
        debug!("Querying path info for: {}", path);

        match self.daemon.lock().await.query_path_info(path).await {
            Ok(info) => Ok(info.path),
            Err(e) => Err(NixServeError::nix_daemon(format!(
                "Failed to query path info: {}",
                e
            ))),
        }
    }

    /// Import a NAR file into the Nix store
    pub async fn import_nar(&self, nar_path: &Path) -> NixServeResult<String> {
        debug!("Importing NAR file: {}", nar_path.display());

        // Use nix-store --import command for now
        // In the future, this could use the daemon protocol directly
        let output = tokio::process::Command::new("nix-store")
            .arg("--import")
            .arg(nar_path)
            .output()
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to import NAR: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NixServeError::nix_daemon(format!(
                "Failed to import NAR: {}",
                stderr
            )));
        }

        let store_path = String::from_utf8(output.stdout)
            .map_err(|e| {
                NixServeError::internal(format!("Invalid UTF-8 in nix-store output: {}", e))
            })?
            .trim()
            .to_string();

        info!("Imported NAR to store path: {}", store_path);

        Ok(store_path)
    }

    /// Stream a NAR file from a store path using callback
    pub async fn stream_nar<F>(&self, path: &str, callback: F) -> NixServeResult<()>
    where
        F: FnMut(Vec<u8>) -> Result<()>,
    {
        debug!("Streaming NAR for path: {}", path);

        self.daemon
            .lock()
            .await
            .stream_nar(path, callback)
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to stream NAR: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_get_real_path() {
        // Test with same virtual and real paths
        let store = Store::new("/nix/store".to_string(), None);
        let path = Path::new("/nix/store/abcdef-test");
        assert_eq!(store.get_real_path(path), path);

        // Test with different virtual and real paths
        let store = Store::new("/nix/store".to_string(), Some("/mnt/nix/store".to_string()));
        let path = Path::new("/nix/store/abcdef-test");
        let expected = Path::new("/mnt/nix/store/abcdef-test");
        assert_eq!(store.get_real_path(path), expected);

        // Test with path not in store
        let store = Store::new("/nix/store".to_string(), Some("/mnt/nix/store".to_string()));
        let path = Path::new("/tmp/some-file");
        assert_eq!(store.get_real_path(path), path);
    }

    #[test]
    fn test_store_accessors() {
        let store = Store::new(
            "/virtual/store".to_string(),
            Some("/real/store".to_string()),
        );
        assert_eq!(store.virtual_store(), "/virtual/store");
        assert_eq!(store.real_store(), Path::new("/real/store"));

        let store = Store::new("/nix/store".to_string(), None);
        assert_eq!(store.virtual_store(), "/nix/store");
        assert_eq!(store.real_store(), Path::new("/nix/store"));
    }
}
