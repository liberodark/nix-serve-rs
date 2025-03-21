use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::info;

use crate::crypto::signing::SigningKey;

const DEFAULT_BIND: &str = "[::]:5000";
const DEFAULT_WORKERS: usize = 4;
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_PRIORITY: usize = 30;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Bind address (format: [host]:port or unix:/path/to/socket)
    #[serde(default = "default_bind")]
    pub bind: String,

    #[serde(default = "default_workers")]
    pub workers: usize,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_priority")]
    pub priority: usize,

    #[serde(default = "default_store_dir")]
    pub virtual_store: String,

    pub real_store: Option<String>,

    #[serde(default)]
    pub sign_key_paths: Vec<String>,

    pub tls_cert_path: Option<String>,

    pub tls_key_path: Option<String>,

    #[serde(skip)]
    pub signing_keys: Vec<SigningKey>,
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
    "/nix/store".to_string()
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
        }
    }
}

impl Config {
    pub fn load(config_path: Option<&str>, args: &impl ArgsProvider) -> Result<Self> {
        let mut config = Config::default();

        if let Some(path) = config_path {
            info!("Loading configuration from {}", path);
            let file_content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {}", path))?;

            config = toml::from_str(&file_content)
                .with_context(|| format!("Failed to parse config file: {}", path))?;
        }

        if let Some(bind) = args.bind() {
            config.bind = bind;
        }

        if let Some(workers) = args.workers() {
            config.workers = workers;
        }

        if let Some(sign_key) = args.sign_key() {
            config.sign_key_paths.push(sign_key);
        }

        if config.workers == 0 {
            config.workers = 1;
        }

        for key_path in &config.sign_key_paths {
            let signing_key = SigningKey::from_file(Path::new(key_path))
                .with_context(|| format!("Failed to load signing key: {}", key_path))?;

            config.signing_keys.push(signing_key);
        }

        Ok(config)
    }

    pub fn real_store(&self) -> &str {
        self.real_store.as_deref().unwrap_or(&self.virtual_store)
    }
}

pub trait ArgsProvider {
    fn bind(&self) -> Option<String>;
    fn workers(&self) -> Option<usize>;
    fn sign_key(&self) -> Option<String>;
}
