use anyhow::{Context, Result};
use tokio::process::Command;

use crate::nix::PathInfo;

/// Communication with the Nix daemon
///
/// Currently, this implementation uses external Nix commands
/// for simplicity and security reasons, rather than direct communication
/// with the Nix daemon.
pub struct NixDaemon {}

impl NixDaemon {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    pub async fn is_valid_path(&mut self, path: &str) -> Result<bool> {
        let output = Command::new("nix-store")
            .arg("--query")
            .arg("--valid")
            .arg(path)
            .output()
            .await
            .context("Failed to execute nix-store --query --valid")?;

        Ok(output.status.success())
    }

    pub async fn query_path_from_hash_part(&mut self, hash_part: &str) -> Result<Option<String>> {
        let output = Command::new("nix-store")
            .arg("--query")
            .arg("--outputs")
            .arg(format!("/nix/store/{}-*", hash_part))
            .output()
            .await
            .context("Failed to execute nix-store --query --outputs")?;

        if output.status.success() {
            let path = String::from_utf8(output.stdout)
                .context("Failed to parse nix-store output")?
                .trim()
                .to_string();

            if path.is_empty() {
                Ok(None)
            } else {
                Ok(Some(path))
            }
        } else {
            Ok(None)
        }
    }

    pub async fn query_path_info(&mut self, path: &str) -> Result<Option<PathInfo>> {
        let is_valid = self.is_valid_path(path).await?;

        if !is_valid {
            return Ok(None);
        }

        let hash_output = Command::new("nix-store")
            .arg("--query")
            .arg("--hash")
            .arg(path)
            .output()
            .await
            .context("Failed to execute nix-store --query --hash")?;

        let hash = String::from_utf8(hash_output.stdout)
            .context("Failed to parse nix-store hash output")?
            .trim()
            .to_string();

        let refs_output = Command::new("nix-store")
            .arg("--query")
            .arg("--references")
            .arg(path)
            .output()
            .await
            .context("Failed to execute nix-store --query --references")?;

        let references = String::from_utf8(refs_output.stdout)
            .context("Failed to parse nix-store references output")?
            .lines()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        let size_output = Command::new("nix-store")
            .arg("--query")
            .arg("--size")
            .arg(path)
            .output()
            .await
            .context("Failed to execute nix-store --query --size")?;

        let nar_size = String::from_utf8(size_output.stdout)
            .context("Failed to parse nix-store size output")?
            .trim()
            .parse::<u64>()
            .context("Failed to parse NAR size")?;

        let deriver_output = Command::new("nix-store")
            .arg("--query")
            .arg("--deriver")
            .arg(path)
            .output()
            .await
            .context("Failed to execute nix-store --query --deriver")?;

        let deriver = String::from_utf8(deriver_output.stdout)
            .context("Failed to parse nix-store deriver output")?
            .trim()
            .to_string();

        let deriver = if deriver == "unknown-deriver" || deriver.is_empty() {
            None
        } else {
            Some(deriver)
        };

        Ok(Some(PathInfo {
            deriver,
            hash,
            references,
            registration_time: 0, // Not available via command line
            nar_size,
            ultimate: false,       // Not available via command line
            sigs: Vec::new(),      // Not available via command line
            content_address: None, // Not available via command line
        }))
    }
}
