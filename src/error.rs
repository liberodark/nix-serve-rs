use thiserror::Error;

/// Custom error types for nix-serve-rs
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
    /// Create a configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::Config(msg.into())
    }

    /// Create a Nix daemon error
    pub fn nix_daemon<S: Into<String>>(msg: S) -> Self {
        Self::NixDaemon(msg.into())
    }

    /// Create a path not found error
    pub fn path_not_found<S: Into<String>>(path: S) -> Self {
        Self::PathNotFound(path.into())
    }

    /// Create an invalid hash error
    pub fn invalid_hash<S: Into<String>>(hash: S) -> Self {
        Self::InvalidHash(hash.into())
    }

    /// Create a cryptographic error
    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        Self::Crypto(msg.into())
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Self::Internal(msg.into())
    }
}

/// Type alias for Results with NixServeError
pub type NixServeResult<T> = Result<T, NixServeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_construction() {
        // Test IO Error
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = NixServeError::from(io_err);
        assert!(matches!(err, NixServeError::Io(_)));

        // Test helper functions
        let config_err = NixServeError::config("bad config");
        assert!(matches!(config_err, NixServeError::Config(_)));

        let daemon_err = NixServeError::nix_daemon("daemon failed");
        assert!(matches!(daemon_err, NixServeError::NixDaemon(_)));

        let path_err = NixServeError::path_not_found("/nix/store/123");
        assert!(matches!(path_err, NixServeError::PathNotFound(_)));

        let hash_err = NixServeError::invalid_hash("abc123");
        assert!(matches!(hash_err, NixServeError::InvalidHash(_)));

        let crypto_err = NixServeError::crypto("signature failed");
        assert!(matches!(crypto_err, NixServeError::Crypto(_)));

        let internal_err = NixServeError::internal("something went wrong");
        assert!(matches!(internal_err, NixServeError::Internal(_)));
    }

    #[test]
    fn test_error_messages() {
        let err = NixServeError::path_not_found("/nix/store/123");
        assert_eq!(format!("{}", err), "Path not found: /nix/store/123");

        let err = NixServeError::config("Invalid config");
        assert_eq!(format!("{}", err), "Configuration error: Invalid config");
    }
}
