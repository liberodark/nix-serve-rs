use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::stream::Stream;
use tokio::process::Command;
use tokio_util::io::ReaderStream;
use tracing::debug;

/// Stream a NAR file for a path in the Nix store
///
/// This function takes ownership of the path (PathBuf) to avoid lifetime issues.
pub async fn stream_nar(
    path: PathBuf,
) -> Result<impl Stream<Item = Result<Bytes, std::io::Error>>> {
    debug!("Streaming NAR for path: {}", path.display());

    let mut cmd = Command::new("nix-store")
        .arg("--dump")
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("Failed to execute nix-store --dump")?;

    let stdout = cmd
        .stdout
        .take()
        .context("Failed to get stdout of nix-store process")?;

    Ok(ReaderStream::new(stdout))
}

pub async fn hash_nar<P>(path: P) -> Result<String>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    debug!("Calculating NAR hash for path: {}", path.display());

    let output = Command::new("nix-hash")
        .arg("--type")
        .arg("sha256")
        .arg("--base32")
        .arg(path)
        .output()
        .await
        .context("Failed to execute nix-hash")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix-hash failed: {}", stderr);
    }

    let hash = String::from_utf8(output.stdout)
        .context("Failed to parse nix-hash output")?
        .trim()
        .to_string();

    Ok(format!("sha256:{}", hash))
}
