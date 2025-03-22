use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::error::{NixServeError, NixServeResult};
use crate::nix::daemon::NixDaemon;
use crate::nix::path_info::PathInfo;

// Cache for path info to reduce duplicate queries
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
    daemon: Arc<Mutex<NixDaemon>>,
    cache: Mutex<PathInfoCache>,
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

        // Try to find in cache first to avoid daemon call
        {
            let cache = self.cache.lock().await;
            for (path, _) in cache.cache.iter() {
                if path.contains(hash_part) {
                    return Ok(Some(path.clone()));
                }
            }
        }

        let mut daemon = self.daemon.lock().await;
        daemon
            .query_path_from_hash_part(hash_part)
            .await
            .map_err(|e| {
                NixServeError::nix_daemon(format!("Failed to query path from hash part: {}", e))
            })
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
        let mut daemon = self.daemon.lock().await;
        let result = daemon
            .query_path_info(path)
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to query path info: {}", e)))?;

        // Update cache if found
        if let Some(ref info) = result {
            let mut cache = self.cache.lock().await;
            cache.insert(path.to_string(), info.clone());
        }

        Ok(result)
    }

    // Store a NAR file in the cache
    pub async fn store_nar(
        &self,
        hash_part: &str,
        nar_hash: &str,
        data: bytes::Bytes,
    ) -> NixServeResult<PathBuf> {
        // Create the directory structure if it doesn't exist
        let real_store_str = self.real_store().to_string();
        let parent_path = Path::new(&real_store_str)
            .parent()
            .ok_or_else(|| NixServeError::internal("Cannot determine NAR directory"))?;
        let nar_dir = parent_path.join("nar");

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

        let output = Command::new("nix-store")
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

    // Get the list of references for a path
    pub async fn query_references(&self, path: &str) -> NixServeResult<Vec<String>> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if let Some(info) = cache.get(path) {
                return Ok(info.references.clone());
            }
        }

        debug!("Querying references for {}", path);
        let output = Command::new("nix-store")
            .arg("--query")
            .arg("--references")
            .arg(path)
            .output()
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to query references: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NixServeError::nix_daemon(format!(
                "Failed to query references: {}",
                stderr
            )));
        }

        let refs = String::from_utf8(output.stdout)
            .map_err(|e| {
                NixServeError::internal(format!("Invalid UTF-8 in nix-store output: {}", e))
            })?
            .lines()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        Ok(refs)
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

        // Check if we have a narinfo directory
        let real_store_str = self.real_store().to_string();
        let parent_path = Path::new(&real_store_str)
            .parent()
            .ok_or_else(|| NixServeError::internal("Cannot determine narinfo directory"))?;

        // Extract hash part from store path
        let hash_part = store_path
            .split('/')
            .last()
            .and_then(|s| s.split('-').next())
            .ok_or_else(|| {
                NixServeError::internal(format!("Invalid store path format: {}", store_path))
            })?;

        // Create narinfo content
        let narinfo_content = format!(
            "StorePath: {}\nURL: nar/{}.nar\nCompression: none\nNarHash: {}\nNarSize: {}\nReferences: {}\n",
            store_path,
            hash_part,
            path_info.hash,
            path_info.nar_size,
            path_info.reference_basenames().join(" ")
        );

        // Write narinfo file
        let narinfo_path = parent_path.join(format!("{}.narinfo", hash_part));
        tokio::fs::write(&narinfo_path, narinfo_content)
            .await
            .map_err(|e| NixServeError::internal(format!("Failed to write narinfo file: {}", e)))?;

        info!("Added {} to binary cache", store_path);

        Ok(())
    }
}
