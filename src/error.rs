use thiserror::Error;

/// Custom error type for nix-serve-rs
#[derive(Error, Debug)]
pub enum NixServeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Nix daemon error: {0}")]
    NixDaemon(String),

    #[error("Path not found: {0}")]
    PathNotFound(String),

    #[error("Invalid hash: {0}")]
    InvalidHash(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl NixServeError {
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::Config(msg.into())
    }

    pub fn nix_daemon<S: Into<String>>(msg: S) -> Self {
        Self::NixDaemon(msg.into())
    }

    pub fn path_not_found<S: Into<String>>(path: S) -> Self {
        Self::PathNotFound(path.into())
    }

    pub fn invalid_hash<S: Into<String>>(hash: S) -> Self {
        Self::InvalidHash(hash.into())
    }

    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Self::Internal(msg.into())
    }
}

pub type NixServeResult<T> = Result<T, NixServeError>;
