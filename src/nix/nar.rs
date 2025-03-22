use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::Stream;
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

// Type alias pour clarifier ce que nous retournons
type NarStream = ReaderStream<tokio::io::Take<tokio::io::BufReader<tokio::fs::File>>>;

/// Stream a NAR file with range support
///
/// This is used for HTTP Range requests
pub async fn stream_nar_with_range(
    path: PathBuf,
    range: Option<&str>,
    total_size: u64,
) -> Result<(NarStream, u64, u64)> {
    // Utiliser la même approche pour les deux cas: créer un fichier temporaire
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join("temp.nar");

    // Dump the NAR to a temp file in both cases
    Command::new("nix-store")
        .arg("--dump")
        .arg(&path)
        .arg("--to-file")
        .arg(&temp_path)
        .output()
        .await
        .context("Failed to create temporary NAR file")?;

    let file = tokio::fs::File::open(&temp_path).await?;
    let file_size = file.metadata().await?.len();

    if file_size != total_size {
        debug!("Expected NAR size {} but got {}", total_size, file_size);
    }

    if let Some(range_str) = range {
        // Parse range request header
        // Format: "bytes=0-1023" or "bytes=1024-"
        let range_parts: Vec<&str> = range_str.trim_start_matches("bytes=").split('-').collect();
        if range_parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid range header format"));
        }

        let start: u64 = range_parts[0].parse().unwrap_or(0);
        let end: u64 = if range_parts[1].is_empty() {
            total_size - 1
        } else {
            range_parts[1].parse().unwrap_or(total_size - 1)
        };

        // Validate range boundaries
        let end = if end >= total_size {
            total_size - 1
        } else {
            end
        };
        if start > end || start >= total_size {
            return Err(anyhow::anyhow!("Invalid range values"));
        }

        let length = end - start + 1;

        debug!(
            "Streaming NAR with range {}-{} for {}",
            start,
            end,
            path.display()
        );

        let mut limited_file = tokio::io::BufReader::new(file);

        // Seek to the start position
        tokio::io::AsyncSeekExt::seek(&mut limited_file, std::io::SeekFrom::Start(start)).await?;

        // Create a limited reader for the range
        let limited_reader = tokio::io::AsyncReadExt::take(limited_file, length);

        Ok((ReaderStream::new(limited_reader), start, end))
    } else {
        // Pour le cas sans range, on utilise quand même la même approche avec un fichier temporaire
        // mais on stream tout le fichier
        let reader = tokio::io::BufReader::new(file);

        // Take the entire file size (effectively no limit)
        let limited_reader = tokio::io::AsyncReadExt::take(reader, file_size);

        Ok((ReaderStream::new(limited_reader), 0, total_size - 1))
    }
}

/// Calculate the hash of a NAR file
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

/// Get the NAR size of a store path
pub async fn get_nar_size<P>(path: P) -> Result<u64>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    debug!("Getting NAR size for path: {}", path.display());

    // Option 1: Use nix-store --dump --to-file /dev/null and measure size
    let output = Command::new("nix-store")
        .arg("--query")
        .arg("--size")
        .arg(path)
        .output()
        .await
        .context("Failed to execute nix-store --query --size")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix-store --query --size failed: {}", stderr);
    }

    let size = String::from_utf8(output.stdout)
        .context("Failed to parse nix-store output")?
        .trim()
        .parse::<u64>()
        .context("Failed to parse NAR size")?;

    Ok(size)
}

/// Structure for NAR file metadata
#[derive(Debug, Clone)]
pub struct NarInfo {
    pub path: String,              // Store path
    pub nar_hash: String,          // NAR hash (sha256:...)
    pub nar_size: u64,             // Size of NAR
    pub compression: String,       // Compression method used
    pub file_hash: Option<String>, // Hash of compressed file if applicable
    pub file_size: Option<u64>,    // Size of compressed file if applicable
}

impl NarInfo {
    pub async fn from_path<P>(store: &Arc<super::store::NixStore>, path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let info = store
            .query_path_info(&path_str)
            .await?
            .context("Path info not found")?;

        Ok(Self {
            path: path_str,
            nar_hash: info.hash.clone(),
            nar_size: info.nar_size,
            compression: "none".to_string(),
            file_hash: None,
            file_size: None,
        })
    }
}
