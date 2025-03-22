use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::signing::SigningKey;
use crate::store::Store;

// Default values for serde
fn default_bind() -> String {
    "[::]:5000".into()
}

fn default_workers() -> usize {
    4
}

fn default_max_connections() -> usize {
    1024
}

fn default_priority() -> usize {
    30
}

fn default_store_dir() -> String {
    "/nix/store".into()
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

/// Main server configuration
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

    /// Binary cache priority
    #[serde(default = "default_priority")]
    pub priority: usize,

    /// Virtual Nix store path (as advertised to clients)
    #[serde(default = "default_store_dir")]
    pub virtual_store: String,

    /// Real Nix store path (where files are actually located)
    pub real_store: Option<String>,

    /// Paths to signing keys
    #[serde(default)]
    pub sign_key_paths: Vec<PathBuf>,

    /// Path to TLS certificate
    pub tls_cert_path: Option<String>,

    /// Path to TLS key
    pub tls_key_path: Option<String>,

    /// In-memory signing keys (parsed from sign_key_paths)
    #[serde(skip)]
    pub signing_keys: Vec<SigningKey>,

    /// Whether to require authenticated uploads
    #[serde(default = "default_false")]
    pub require_auth_uploads: bool,

    /// Whether to compress NARs when serving them
    #[serde(default = "default_false")]
    pub compress_nars: bool,

    /// Compression level (1-19 for zstd, 0-9 for xz)
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,

    /// Compression format to use (zstd or xz)
    #[serde(default = "default_compression_format")]
    pub compression_format: String,

    /// Configured store instance
    #[serde(skip)]
    pub store: Store,
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
            store: Store::new(default_store_dir(), None),
        }
    }
}

impl Config {
    /// Load configuration from a file
    pub fn load(settings_file: &Path) -> Result<Self> {
        toml::from_str(
            &fs::read_to_string(settings_file).with_context(|| {
                format!("Failed to read config file: {}", settings_file.display())
            })?,
        )
        .with_context(|| format!("Failed to parse config file: {}", settings_file.display()))
    }

    /// Load configuration from environment and files
    pub fn load_from_env() -> Result<Self> {
        // Start with default configuration
        let mut config = match std::env::var("CONFIG_FILE") {
            Ok(path) => Self::load(Path::new(&path))?,
            Err(_) => {
                if Path::new("settings.toml").exists() {
                    Self::load(Path::new("settings.toml"))?
                } else {
                    Config::default()
                }
            }
        };

        // Check workers
        if config.workers == 0 {
            warn!("workers must be greater than 0, setting to 1");
            config.workers = 1;
        }

        // Load from environment variables
        Self::load_from_env_vars(&mut config);

        // Load signing keys
        Self::load_signing_keys(&mut config)?;

        // Configure the store
        config.store = Store::new(config.virtual_store.clone(), config.real_store.clone());

        // Validate configuration
        Self::validate(&mut config)?;

        Ok(config)
    }

    /// Load values from environment variables
    fn load_from_env_vars(config: &mut Self) {
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
            config.sign_key_paths.push(PathBuf::from(sign_key_path));
        }

        if let Ok(sign_key_paths) = env::var("NIX_SECRET_KEY_FILES") {
            for path in sign_key_paths.split_whitespace() {
                config.sign_key_paths.push(PathBuf::from(path));
            }
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

    /// Load signing keys from configured paths
    fn load_signing_keys(config: &mut Self) -> Result<()> {
        for sign_key_path in &config.sign_key_paths {
            let signing_key =
                crate::signing::parse_secret_key(sign_key_path).with_context(|| {
                    format!("Failed to load signing key: {}", sign_key_path.display())
                })?;

            config.signing_keys.push(signing_key);
        }

        Ok(())
    }

    /// Validate configuration and adjust values if necessary
    fn validate(config: &mut Self) -> Result<()> {
        // Validate TLS configuration
        if config.tls_cert_path.is_some() != config.tls_key_path.is_some() {
            bail!("TLS configuration requires both cert and key files");
        }

        // Validate compression format
        if !["xz", "zstd"].contains(&config.compression_format.as_str()) {
            warn!(
                "Invalid compression format {}, using default of 'xz'",
                config.compression_format
            );
            config.compression_format = "xz".to_string();
        }

        // Validate compression level
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
                // Should never happen due to previous validation
                config.compression_format = "xz".to_string();
                config.compression_level = 3;
            }
        }

        Ok(())
    }

    /// Get the real store path
    pub fn real_store(&self) -> &str {
        self.real_store.as_deref().unwrap_or(&self.virtual_store)
    }
}

/// Trait for argument providers (CLI, etc.)
pub trait ArgsProvider {
    fn bind(&self) -> Option<String>;
    fn workers(&self) -> Option<usize>;
    fn sign_key(&self) -> Option<String>;
    fn compress_nars(&self) -> Option<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.bind, "[::]:5000");
        assert_eq!(config.workers, 4);
        assert_eq!(config.priority, 30);
        assert_eq!(config.virtual_store, "/nix/store");
        assert!(config.real_store.is_none());
        assert!(!config.compress_nars);
        assert_eq!(config.compression_format, "xz");
        assert_eq!(config.compression_level, 3);
    }

    #[test]
    fn test_load_from_toml() -> Result<()> {
        let dir = tempdir()?;
        let config_path = dir.path().join("config.toml");

        let config_content = r#"
        bind = "127.0.0.1:8080"
        workers = 8
        priority = 20
        virtual_store = "/custom/store"
        real_store = "/actual/store"
        compress_nars = true
        compression_level = 5
        compression_format = "zstd"
        "#;

        let mut file = std::fs::File::create(&config_path)?;
        write!(file, "{}", config_content)?;

        let config = Config::load(&config_path)?;

        assert_eq!(config.bind, "127.0.0.1:8080");
        assert_eq!(config.workers, 8);
        assert_eq!(config.priority, 20);
        assert_eq!(config.virtual_store, "/custom/store");
        assert_eq!(config.real_store, Some("/actual/store".to_string()));
        assert!(config.compress_nars);
        assert_eq!(config.compression_level, 5);
        assert_eq!(config.compression_format, "zstd");

        Ok(())
    }

    #[test]
    fn test_validation() -> Result<()> {
        // Test compression format validation
        let mut config = Config::default();
        config.compression_format = "invalid".to_string();
        Config::validate(&mut config)?;
        assert_eq!(config.compression_format, "xz");

        // Test xz compression level validation
        config.compression_format = "xz".to_string();
        config.compression_level = 15;
        Config::validate(&mut config)?;
        assert_eq!(config.compression_level, 3);

        // Test zstd compression level validation
        config.compression_format = "zstd".to_string();
        config.compression_level = 0;
        Config::validate(&mut config)?;
        assert_eq!(config.compression_level, 3);

        // Test TLS validation - cert without key
        config.tls_cert_path = Some("cert.pem".to_string());
        config.tls_key_path = None;
        assert!(Config::validate(&mut config).is_err());

        // Valid TLS config
        config.tls_cert_path = Some("cert.pem".to_string());
        config.tls_key_path = Some("key.pem".to_string());
        assert!(Config::validate(&mut config).is_ok());

        Ok(())
    }
}
