use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

use crate::crypto::signing::SigningKey;

const DEFAULT_BIND: &str = "[::]:5000";
const DEFAULT_WORKERS: usize = 4;
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_PRIORITY: usize = 30;
const DEFAULT_STORE_DIR: &str = "/nix/store";

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Bind address (format: [host]:port or unix:/path/to/socket)
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Number of worker threads
    #[serde(default = "default_workers")]
    pub workers: usize,

    /// Maximum number of connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Priority for the binary cache
    #[serde(default = "default_priority")]
    pub priority: usize,

    /// Path to the virtual Nix store (as advertised to clients)
    #[serde(default = "default_store_dir")]
    pub virtual_store: String,

    /// Path to the real Nix store (where files are actually located)
    pub real_store: Option<String>,

    /// Paths to signing keys
    #[serde(default)]
    pub sign_key_paths: Vec<String>,

    /// Path to TLS certificate
    pub tls_cert_path: Option<String>,

    /// Path to TLS key
    pub tls_key_path: Option<String>,

    /// In-memory signing keys (parsed from sign_key_paths)
    #[serde(skip)]
    pub signing_keys: Vec<SigningKey>,

    /// Whether to require authenticated uploads (clients must provide a valid signature)
    #[serde(default = "default_false")]
    pub require_auth_uploads: bool,

    /// Whether to compress NARs when serving them (zstd or xz compression)
    #[serde(default = "default_false")]
    pub compress_nars: bool,

    /// Compression level (1-19 for zstd, 0-9 for xz)
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,

    /// Compression format to use (zstd or xz)
    #[serde(default = "default_compression_format")]
    pub compression_format: String,
}

fn default_bind() -> String {
    DEFAULT_BIND.to_string()
}

fn default_workers() -> usize {
    DEFAULT_WORKERS
}

fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

fn default_priority() -> usize {
    DEFAULT_PRIORITY
}

fn default_store_dir() -> String {
    DEFAULT_STORE_DIR.to_string()
}

fn default_false() -> bool {
    false
}

fn default_compression_level() -> i32 {
    3
}

fn default_compression_format() -> String {
    "xz".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            workers: default_workers(),
            max_connections: default_max_connections(),
            priority: default_priority(),
            virtual_store: default_store_dir(),
            real_store: None,
            sign_key_paths: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
            signing_keys: Vec::new(),
            require_auth_uploads: false,
            compress_nars: false,
            compression_level: default_compression_level(),
            compression_format: default_compression_format(),
        }
    }
}

impl Config {
    pub fn load(config_path: Option<&str>, args: &impl ArgsProvider) -> Result<Self> {
        // Start with default configuration
        let mut config = Config::default();

        // Try to load from environment variables first
        Self::load_from_env(&mut config);

        // Then load from config file if provided
        if let Some(path) = config_path {
            info!("Loading configuration from {}", path);
            let file_content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {}", path))?;

            config = toml::from_str(&file_content)
                .with_context(|| format!("Failed to parse config file: {}", path))?;
        }

        // Override with command line arguments
        if let Some(bind) = args.bind() {
            config.bind = bind;
        }

        if let Some(workers) = args.workers() {
            config.workers = workers;
        }

        if let Some(sign_key) = args.sign_key() {
            config.sign_key_paths.push(sign_key);
        }

        if let Some(compress) = args.compress_nars() {
            config.compress_nars = compress;
        }

        // Validate configuration
        Self::validate(&mut config)?;

        // Load signing keys
        for key_path in &config.sign_key_paths {
            let signing_key = SigningKey::from_file(Path::new(key_path))
                .with_context(|| format!("Failed to load signing key: {}", key_path))?;

            config.signing_keys.push(signing_key);
        }

        Ok(config)
    }

    fn load_from_env(config: &mut Config) {
        if let Ok(bind) = env::var("NIX_SERVE_BIND") {
            config.bind = bind;
        }

        if let Ok(workers) = env::var("NIX_SERVE_WORKERS") {
            if let Ok(workers) = workers.parse() {
                config.workers = workers;
            }
        }

        if let Ok(max_connections) = env::var("NIX_SERVE_MAX_CONNECTIONS") {
            if let Ok(max_connections) = max_connections.parse() {
                config.max_connections = max_connections;
            }
        }

        if let Ok(priority) = env::var("NIX_SERVE_PRIORITY") {
            if let Ok(priority) = priority.parse() {
                config.priority = priority;
            }
        }

        if let Ok(virtual_store) = env::var("NIX_SERVE_VIRTUAL_STORE") {
            config.virtual_store = virtual_store;
        }

        if let Ok(real_store) = env::var("NIX_SERVE_REAL_STORE") {
            config.real_store = Some(real_store);
        }

        if let Ok(sign_key_path) = env::var("NIX_SECRET_KEY_FILE") {
            config.sign_key_paths.push(sign_key_path);
        }

        if let Ok(tls_cert) = env::var("NIX_SERVE_TLS_CERT") {
            config.tls_cert_path = Some(tls_cert);
        }

        if let Ok(tls_key) = env::var("NIX_SERVE_TLS_KEY") {
            config.tls_key_path = Some(tls_key);
        }

        if let Ok(require_auth) = env::var("NIX_SERVE_REQUIRE_AUTH") {
            config.require_auth_uploads = require_auth.to_lowercase() == "true";
        }

        if let Ok(compress) = env::var("NIX_SERVE_COMPRESS") {
            config.compress_nars = compress.to_lowercase() == "true";
        }

        if let Ok(level) = env::var("NIX_SERVE_COMPRESSION_LEVEL") {
            if let Ok(level) = level.parse() {
                config.compression_level = level;
            }
        }

        if let Ok(format) = env::var("NIX_SERVE_COMPRESSION_FORMAT") {
            config.compression_format = format.to_lowercase();
        }
    }

    fn validate(config: &mut Config) -> Result<()> {
        // Enforce at least 1 worker
        if config.workers == 0 {
            warn!("workers must be greater than 0, setting to 1");
            config.workers = 1;
        }

        // Check TLS configuration
        if config.tls_cert_path.is_some() != config.tls_key_path.is_some() {
            bail!("TLS configuration requires both cert and key files");
        }

        // Check compression format
        if !["xz", "zstd"].contains(&config.compression_format.as_str()) {
            warn!(
                "Invalid compression format {}, using default of 'xz'",
                config.compression_format
            );
            config.compression_format = "xz".to_string();
        }

        // Check compression level
        match config.compression_format.as_str() {
            "xz" => {
                if config.compression_level < 0 || config.compression_level > 9 {
                    warn!(
                        "Invalid xz compression level {}, using default of 3",
                        config.compression_level
                    );
                    config.compression_level = 3;
                }
            }
            "zstd" => {
                if config.compression_level < 1 || config.compression_level > 19 {
                    warn!(
                        "Invalid zstd compression level {}, using default of 3",
                        config.compression_level
                    );
                    config.compression_level = 3;
                }
            }
            _ => {
                // We already validated format above, this should never happen
                config.compression_format = "xz".to_string();
                config.compression_level = 3;
            }
        }

        Ok(())
    }

    pub fn real_store(&self) -> &str {
        self.real_store.as_deref().unwrap_or(&self.virtual_store)
    }
}

pub trait ArgsProvider {
    fn bind(&self) -> Option<String>;
    fn workers(&self) -> Option<usize>;
    fn sign_key(&self) -> Option<String>;
    fn compress_nars(&self) -> Option<bool>;
}
