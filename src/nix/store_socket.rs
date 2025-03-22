use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use bytes::Bytes;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::error::{NixServeError, NixServeResult};
use crate::nix::daemon_protocol::{NixDaemonProtocol, PathInfo as DaemonPathInfo};
use crate::nix::path_info::PathInfo;

// Cache structure to reduce duplicate queries
struct PathInfoCache {
    cache: HashMap<String, PathInfo>,
    max_size: usize,
}

impl PathInfoCache {
    fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_size),
            max_size,
        }
    }

    fn get(&self, path: &str) -> Option<&PathInfo> {
        self.cache.get(path)
    }

    fn insert(&mut self, path: String, info: PathInfo) {
        // Simple eviction strategy: if cache is full, remove oldest entries
        if self.cache.len() >= self.max_size {
            // Remove arbitrary entries (in practice, this would be LRU)
            if let Some(key) = self.cache.keys().next().cloned() {
                self.cache.remove(&key);
            }
        }
        self.cache.insert(path, info);
    }
}

pub struct NixStore {
    virtual_store: String,
    real_store: String,
    daemon: Mutex<NixDaemonProtocol>,
    cache: Mutex<PathInfoCache>,
}

// Helper function to convert between PathInfo types
fn convert_path_info(daemon_info: DaemonPathInfo) -> PathInfo {
    PathInfo {
        deriver: daemon_info.deriver,
        hash: daemon_info.hash,
        references: daemon_info.references,
        registration_time: daemon_info.registration_time,
        nar_size: daemon_info.nar_size,
        ultimate: daemon_info.ultimate,
        sigs: daemon_info.sigs,
        content_address: daemon_info.content_address,
    }
}

impl NixStore {
    pub fn new(virtual_store: &str, real_store: Option<&str>) -> Result<Self> {
        info!("Initializing Nix store (socket): virtual={}", virtual_store);
        if let Some(real) = real_store {
            info!("Using real Nix store: {}", real);
        }

        let daemon = NixDaemonProtocol::new();

        Ok(Self {
            virtual_store: virtual_store.to_string(),
            real_store: real_store.unwrap_or(virtual_store).to_string(),
            daemon: Mutex::new(daemon),
            cache: Mutex::new(PathInfoCache::new(1000)),
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
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if cache.get(path).is_some() {
                return Ok(true);
            }
        }

        // Use the protocol directly
        match self.daemon.lock().await.is_valid_path(path).await {
            Ok(valid) => Ok(valid),
            Err(e) => Err(NixServeError::nix_daemon(format!(
                "Failed to check path validity: {}",
                e
            ))),
        }
    }

    pub async fn query_path_from_hash_part(
        &self,
        hash_part: &str,
    ) -> NixServeResult<Option<String>> {
        debug!("Looking up path for hash part: {}", hash_part);

        // Try to find in cache first to avoid daemon call
        {
            let cache = self.cache.lock().await;
            for (path, _) in cache.cache.iter() {
                if path.contains(hash_part) {
                    debug!("Found path in cache: {}", path);
                    return Ok(Some(path.clone()));
                }
            }
        }

        // Query from daemon directly
        match self
            .daemon
            .lock()
            .await
            .query_path_from_hash_part(hash_part)
            .await
        {
            Ok(result) => Ok(result),
            Err(e) => {
                // Try fallback command-line method if daemon fails
                debug!("Daemon protocol failed, using fallback command: {}", e);
                self.query_path_from_hash_part_fallback(hash_part).await
            }
        }
    }

    // Fallback method using command-line tools
    async fn query_path_from_hash_part_fallback(
        &self,
        hash_part: &str,
    ) -> NixServeResult<Option<String>> {
        debug!(
            "Using fallback command-line method for hash part: {}",
            hash_part
        );

        let output = tokio::process::Command::new("nix-store")
            .arg("--query")
            .arg("--outputs")
            .arg(format!("/nix/store/{}-*", hash_part))
            .output()
            .await
            .map_err(|e| {
                NixServeError::nix_daemon(format!("Failed to execute nix-store: {}", e))
            })?;

        if output.status.success() {
            let path = String::from_utf8(output.stdout)
                .map_err(|e| NixServeError::nix_daemon(format!("Invalid UTF-8 in output: {}", e)))?
                .trim()
                .to_string();

            if path.is_empty() {
                debug!("No path found for hash part (fallback): {}", hash_part);
                Ok(None)
            } else {
                debug!(
                    "Found path for hash part {} (fallback): {}",
                    hash_part, path
                );
                Ok(Some(path))
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("nix-store command failed: {}", stderr);
            Ok(None)
        }
    }

    pub async fn query_path_info(&self, path: &str) -> NixServeResult<Option<PathInfo>> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if let Some(info) = cache.get(path) {
                return Ok(Some(info.clone()));
            }
        }

        // Not in cache, query from daemon
        match self.daemon.lock().await.query_path_info(path).await {
            Ok(daemon_info) => {
                // Convert from daemon's PathInfo to our PathInfo
                let path_info = convert_path_info(daemon_info);

                // Update cache
                let mut cache = self.cache.lock().await;
                cache.insert(path.to_string(), path_info.clone());

                Ok(Some(path_info))
            }
            Err(e) => {
                if e.to_string().contains("Path not found") {
                    Ok(None) // Path not found
                } else {
                    Err(NixServeError::nix_daemon(format!(
                        "Failed to query path info: {}",
                        e
                    )))
                }
            }
        }
    }

    // Store a NAR file in the cache
    pub async fn store_nar(
        &self,
        hash_part: &str,
        nar_hash: &str,
        data: Bytes,
    ) -> NixServeResult<PathBuf> {
        // Create the directory structure if it doesn't exist
        let store_root = Path::new(&self.real_store);
        let nar_dir = if store_root.is_absolute() {
            // If real_store is absolute like /nix/store, store NARs in parent/nar
            let parent_path = store_root.parent().ok_or_else(|| {
                NixServeError::internal("Cannot determine NAR directory, real_store has no parent")
            })?;
            parent_path.join("nar")
        } else {
            // If real_store is relative like in a custom location, create nar dir inside
            store_root.join("nar")
        };

        tokio::fs::create_dir_all(&nar_dir).await.map_err(|e| {
            NixServeError::internal(format!("Failed to create NAR directory: {}", e))
        })?;

        // Determine the filename - use both hash part and NAR hash to ensure uniqueness
        let filename = if let Some(stripped) = nar_hash.strip_prefix("sha256:") {
            format!("{}-{}.nar", hash_part, stripped)
        } else {
            format!("{}-{}.nar", hash_part, nar_hash)
        };

        let nar_path = nar_dir.join(&filename);

        // Write the NAR data to the file
        let mut file = File::create(&nar_path)
            .await
            .map_err(|e| NixServeError::internal(format!("Failed to create NAR file: {}", e)))?;

        file.write_all(&data)
            .await
            .map_err(|e| NixServeError::internal(format!("Failed to write NAR data: {}", e)))?;

        info!("Stored NAR file at {}", nar_path.display());

        Ok(nar_path)
    }

    // Import a NAR file into the Nix store
    pub async fn import_nar(&self, nar_path: &Path) -> NixServeResult<String> {
        debug!("Importing NAR file: {}", nar_path.display());

        // Read the NAR file
        let nar_data = tokio::fs::read(nar_path)
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to read NAR file: {}", e)))?;

        // Import the NAR using the daemon protocol
        match self.daemon.lock().await.import_nar(&nar_data).await {
            Ok(store_path) => {
                info!("Imported NAR to store path: {}", store_path);
                Ok(store_path)
            }
            Err(e) => Err(NixServeError::nix_daemon(format!(
                "Failed to import NAR: {}",
                e
            ))),
        }
    }

    // Add a NAR to the binary cache
    pub async fn add_to_binary_cache(
        &self,
        store_path: &str,
        _nar_path: &Path,
    ) -> NixServeResult<()> {
        debug!("Adding {} to binary cache", store_path);

        // Get path info
        let path_info = self
            .query_path_info(store_path)
            .await?
            .ok_or_else(|| NixServeError::path_not_found(store_path.to_string()))?;

        // Extract hash part from store path
        let hash_part = store_path
            .split('/')
            .last()
            .and_then(|s| s.split('-').next())
            .ok_or_else(|| {
                NixServeError::internal(format!("Invalid store path format: {}", store_path))
            })?;

        // Determine the directory to store narinfo files
        // This typically matches the logic in store_nar
        let store_root = Path::new(&self.real_store);
        let narinfo_dir = if store_root.is_absolute() {
            store_root
                .parent()
                .ok_or_else(|| {
                    NixServeError::internal(
                        "Cannot determine narinfo directory, real_store has no parent",
                    )
                })?
                .to_path_buf()
        } else {
            store_root.to_path_buf()
        };

        // Create narinfo content
        let narinfo_content = format!(
            "StorePath: {}\nURL: nar/{}.nar\nCompression: none\nNarHash: {}\nNarSize: {}\nReferences: {}\n",
            store_path,
            hash_part,
            path_info.hash,
            path_info.nar_size,
            path_info.references.join(" ")
        );

        // Write narinfo file
        let narinfo_path = narinfo_dir.join(format!("{}.narinfo", hash_part));
        tokio::fs::write(&narinfo_path, narinfo_content)
            .await
            .map_err(|e| NixServeError::internal(format!("Failed to write narinfo file: {}", e)))?;

        info!(
            "Added {} to binary cache with narinfo at {}",
            store_path,
            narinfo_path.display()
        );

        Ok(())
    }
}
