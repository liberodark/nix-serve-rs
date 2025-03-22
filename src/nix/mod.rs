pub mod daemon;
pub mod daemon_protocol;
pub mod nar;
pub mod path_info;
pub mod store;
pub mod store_socket;

// Re-export common types from path_info for convenience
pub use path_info::PathInfo;

// Helpful error type specific to Nix operations
pub struct NoSuchPath;

impl std::fmt::Display for NoSuchPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Path does not exist in the Nix store")
    }
}

impl std::fmt::Debug for NoSuchPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoSuchPath")
    }
}

impl std::error::Error for NoSuchPath {}

/// Helper function to create a fingerprint for a path in the Nix store
///
/// This is used for signing narinfo files
pub fn fingerprint_path(
    store_dir: &str,
    store_path: &str,
    nar_hash: &str,
    nar_size: u64,
    references: &[String],
) -> Option<String> {
    // Ensure the path is in the store
    if !store_path.starts_with(store_dir) {
        return None;
    }

    // Ensure the hash is in the expected format
    if !nar_hash.starts_with("sha256:") {
        return None;
    }

    // Format the references as a comma-separated list
    let refs_str = references.join(",");

    // Create the fingerprint
    let fingerprint = format!("1;{};{};{};{}", store_path, nar_hash, nar_size, refs_str);

    Some(fingerprint)
}
