use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use bytes::Bytes;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::config::Config;
use crate::crypto::signing::convert_base16_to_nix32;
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
    pub daemon: Mutex<NixDaemonProtocol>,
    cache: Mutex<PathInfoCache>,
    config: Config,
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

        // Initialize the daemon connection
        let daemon = NixDaemonProtocol::new();

        // Create a default config (will be updated later)
        let config = Config::default();

        Ok(Self {
            virtual_store: virtual_store.to_string(),
            real_store: real_store.unwrap_or(virtual_store).to_string(),
            daemon: Mutex::new(daemon),
            cache: Mutex::new(PathInfoCache::new(1000)),
            config,
        })
    }

    // Set the config (call this after initialization)
    pub fn set_config(&mut self, config: Config) {
        self.config = config;
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

        // Query via daemon protocol
        match self.daemon.lock().await.is_valid_path(path).await {
            Ok(valid) => Ok(valid),
            Err(e) => {
                debug!("Daemon protocol failed for is_valid_path: {}", e);

                // Fallback to command line
                let output = tokio::process::Command::new("nix-store")
                    .arg("--query")
                    .arg("--valid")
                    .arg(path)
                    .output()
                    .await
                    .map_err(|e| {
                        NixServeError::nix_daemon(format!("Failed to execute nix-store: {}", e))
                    })?;

                Ok(output.status.success())
            }
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

        // Not in cache, query from daemon directly
        match self
            .daemon
            .lock()
            .await
            .query_path_from_hash_part(hash_part)
            .await
        {
            Ok(result) => Ok(result),
            Err(e) => {
                debug!("Daemon protocol failed: {}", e);

                // If direct daemon call fails, try fallback method
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
                        .map_err(|e| {
                            NixServeError::nix_daemon(format!("Invalid UTF-8 in output: {}", e))
                        })?
                        .trim()
                        .to_string();

                    if path.is_empty() {
                        debug!("No path found for hash part: {}", hash_part);
                        Ok(None)
                    } else {
                        debug!("Found path for hash part {}: {}", hash_part, path);
                        Ok(Some(path))
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    debug!("nix-store command failed: {}", stderr);
                    Ok(None)
                }
            }
        }
    }

    pub async fn query_path_info(&self, path: &str) -> NixServeResult<Option<PathInfo>> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if let Some(info) = cache.get(path) {
                debug!("Path info found in cache for: {}", path);
                return Ok(Some(info.clone()));
            }
        }

        // Not in cache, query from daemon
        let result = match self.daemon.lock().await.query_path_info(path).await {
            Ok(daemon_info) => {
                debug!("Got path info from daemon for: {}", path);
                // Convert daemon PathInfo to our PathInfo
                let info = convert_path_info(daemon_info);

                // Cache the result
                {
                    let mut cache = self.cache.lock().await;
                    cache.insert(path.to_string(), info.clone());
                }

                Some(info)
            }
            Err(e) => {
                debug!("Failed to query path info via daemon: {}", e);

                // If direct daemon call fails, check if path is valid first
                if !self.is_valid_path(path).await? {
                    debug!("Path is not valid: {}", path);
                    return Ok(None);
                }

                // Fallback to command-line approach
                match self.query_path_info_fallback(path).await {
                    Ok(Some(info)) => {
                        debug!("Got path info via fallback for: {}", path);
                        // Cache the result
                        {
                            let mut cache = self.cache.lock().await;
                            cache.insert(path.to_string(), info.clone());
                        }
                        Some(info)
                    }
                    Ok(None) => None,
                    Err(e) => {
                        debug!("Failed to query path info via fallback: {}", e);
                        None
                    }
                }
            }
        };

        Ok(result)
    }

    // Fallback method to get path info using command line
    async fn query_path_info_fallback(&self, path: &str) -> Result<Option<PathInfo>> {
        debug!("Using fallback to query path info: {}", path);

        // Get hash
        let hash_output = tokio::process::Command::new("nix-store")
            .arg("--query")
            .arg("--hash")
            .arg(path)
            .output()
            .await?;

        if !hash_output.status.success() {
            debug!("Failed to get hash for path: {}", path);
            return Ok(None);
        }

        let raw_hash = String::from_utf8(hash_output.stdout)?.trim().to_string();
        debug!("Raw hash from nix-store command: {}", raw_hash);

        // Convert the hash to base32 if it's in hex format and add sha256: prefix
        let hash = if raw_hash.starts_with("sha256:") {
            raw_hash
        } else if raw_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            // Try to convert from hex to base32
            debug!("Converting hash from hex: {}", raw_hash);
            match convert_base16_to_nix32(&raw_hash) {
                Ok(base32) => {
                    debug!("Converted to base32: {}", base32);
                    format!("sha256:{}", base32)
                }
                Err(e) => {
                    debug!("Failed to convert hash to base32: {}", e);
                    format!("sha256:{}", raw_hash)
                }
            }
        } else {
            format!("sha256:{}", raw_hash)
        };

        debug!("Final hash format: {}", hash);

        // Get NAR size
        let size_output = tokio::process::Command::new("nix-store")
            .arg("--query")
            .arg("--size")
            .arg(path)
            .output()
            .await?;

        if !size_output.status.success() {
            debug!("Failed to get size for path: {}", path);
            return Ok(None);
        }

        let nar_size = String::from_utf8(size_output.stdout)?
            .trim()
            .parse::<u64>()?;

        // Get references
        let refs_output = tokio::process::Command::new("nix-store")
            .arg("--query")
            .arg("--references")
            .arg(path)
            .output()
            .await?;

        if !refs_output.status.success() {
            debug!("Failed to get references for path: {}", path);
            return Ok(None);
        }

        let references = String::from_utf8(refs_output.stdout)?
            .lines()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        // Get deriver
        let deriver_output = tokio::process::Command::new("nix-store")
            .arg("--query")
            .arg("--deriver")
            .arg(path)
            .output()
            .await?;

        let deriver = if deriver_output.status.success() {
            let deriver = String::from_utf8(deriver_output.stdout)?.trim().to_string();

            if deriver == "unknown-deriver" || deriver.is_empty() {
                None
            } else {
                Some(deriver)
            }
        } else {
            None
        };

        // Construct a PathInfo object
        let info = PathInfo {
            deriver,
            hash,
            references,
            registration_time: 0, // Not easily available from command line
            nar_size,
            ultimate: false,       // Not easily available from command line
            sigs: Vec::new(),      // Not easily available from command line
            content_address: None, // Not easily available from command line
        };

        debug!("Created PathInfo with hash: {}", info.hash);

        Ok(Some(info))
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

        // Ensure parent directories exist
        if let Some(parent) = nar_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                NixServeError::internal(format!("Failed to create parent directory: {}", e))
            })?;
        }

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

        // Read the NAR data
        let nar_data = tokio::fs::read(nar_path)
            .await
            .map_err(|e| NixServeError::nix_daemon(format!("Failed to read NAR file: {}", e)))?;

        // Create a basename from the path
        let basename = nar_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "imported.nar".to_string());

        // Try to import using the daemon protocol directly
        match self
            .daemon
            .lock()
            .await
            .add_to_store_nar(&nar_data, &basename)
            .await
        {
            Ok(store_path) => {
                info!("Imported NAR to store path: {}", store_path);
                Ok(store_path)
            }
            Err(e) => {
                debug!("Failed to import NAR using daemon protocol: {}", e);

                // Fallback to command-line approach if daemon protocol fails
                let output = tokio::process::Command::new("nix-store")
                    .arg("--import")
                    .arg(nar_path)
                    .output()
                    .await
                    .map_err(|e| {
                        NixServeError::nix_daemon(format!("Failed to execute nix-store: {}", e))
                    })?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(NixServeError::nix_daemon(format!(
                        "Failed to import NAR using nix-store command: {}",
                        stderr
                    )));
                }

                let store_path = String::from_utf8(output.stdout)
                    .map_err(|e| {
                        NixServeError::internal(format!("Invalid UTF-8 in nix-store output: {}", e))
                    })?
                    .trim()
                    .to_string();

                info!("Imported NAR to store path (fallback): {}", store_path);
                Ok(store_path)
            }
        }
    }

    // Add a NAR to the binary cache
    pub async fn add_to_binary_cache(
        &self,
        store_path: &str,
        _nar_path: &Path,
    ) -> NixServeResult<()> {
        debug!("Adding {} to binary cache", store_path);

        // Extract hash part from store path
        let hash_part = store_path
            .split('/')
            .last()
            .and_then(|s| s.split('-').next())
            .ok_or_else(|| {
                NixServeError::internal(format!("Invalid store path format: {}", store_path))
            })?;

        debug!("Extracted hash part: {}", hash_part);

        // Query path info using the daemon socket
        let path_info = match self.daemon.lock().await.query_path_info(store_path).await {
            Ok(daemon_info) => {
                // Convert from daemon's PathInfo to our PathInfo
                convert_path_info(daemon_info)
            }
            Err(e) => {
                debug!("Failed to query path info via daemon: {}", e);

                // Try fallback method
                match self.query_path_info_fallback(store_path).await {
                    Ok(Some(info)) => info,
                    _ => {
                        return Err(NixServeError::nix_daemon(format!(
                            "Failed to query path info: {}",
                            e
                        )))
                    }
                }
            }
        };

        // Log the raw hash from the daemon
        debug!("Raw hash from daemon: {}", path_info.hash);

        // Convert the hash exactly as Harmonia does
        // First, strip any "sha256:" prefix if present
        let hash_hex = if path_info.hash.starts_with("sha256:") {
            path_info.hash[7..].to_string()
        } else {
            path_info.hash.clone()
        };

        // Convert from base16 to base32
        let hash_base32 = match convert_base16_to_nix32(&hash_hex) {
            Ok(base32) => base32,
            Err(e) => {
                debug!("Failed to convert hash to base32: {}", e);
                return Err(NixServeError::internal(format!(
                    "Failed to convert hash to base32: {}",
                    e
                )));
            }
        };

        // Format with sha256: prefix
        let nar_hash = format!("sha256:{}", hash_base32);
        debug!("Formatted NAR hash: {}", nar_hash);

        // Determine the directory to store narinfo files
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

        // Make sure the directory exists
        tokio::fs::create_dir_all(&narinfo_dir).await.map_err(|e| {
            NixServeError::internal(format!("Failed to create narinfo directory: {}", e))
        })?;

        // Create URL based on compression settings
        let url = if self.config.compress_nars {
            format!(
                "nar/{}.nar.{}?hash={}",
                hash_base32, self.config.compression_format, hash_part
            )
        } else {
            format!("nar/{}.nar?hash={}", hash_base32, hash_part)
        };

        // Get reference basenames
        let ref_basenames = path_info
            .references
            .iter()
            .filter_map(|r| {
                Path::new(r)
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
            })
            .collect::<Vec<_>>()
            .join(" ");

        // Create narinfo content
        let narinfo_content = format!(
            "StorePath: {}\nURL: {}\nCompression: {}\nFileHash: {}\nFileSize: {}\nNarHash: {}\nNarSize: {}\nReferences: {}\n",
            store_path,
            url,
            if self.config.compress_nars { &self.config.compression_format } else { "none" },
            nar_hash,
            path_info.nar_size,
            nar_hash,
            path_info.nar_size,
            ref_basenames
        );

        // Log the narinfo content for debugging
        debug!("Generated narinfo content:\n{}", narinfo_content);

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
