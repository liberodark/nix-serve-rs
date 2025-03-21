use serde::{Deserialize, Serialize};

/// Information about a path in the Nix store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    pub deriver: Option<String>,
    pub hash: String,
    pub references: Vec<String>,
    pub registration_time: u64,
    pub nar_size: u64,
    pub ultimate: bool,
    pub sigs: Vec<String>,
    pub content_address: Option<String>,
}

impl PathInfo {
    pub fn extract_basename(path: &str) -> Option<String> {
        path.split('/').last().map(|s| s.to_string())
    }

    pub fn deriver_basename(&self) -> Option<String> {
        self.deriver
            .as_ref()
            .and_then(|d| Self::extract_basename(d))
    }

    pub fn reference_basenames(&self) -> Vec<String> {
        self.references
            .iter()
            .filter_map(|r| Self::extract_basename(r))
            .collect()
    }
}
