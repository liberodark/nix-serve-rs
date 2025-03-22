// Ceci est une version corrigée de daemon_protocol.rs avec les avertissements résolus

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, warn};

const SOCKET_PATH: &str = "/nix/var/nix/daemon-socket/socket";
const MAX_STRING_SIZE: u64 = 0x1000000; // 16M
const MAX_STRING_LIST_SIZE: u64 = 0x10000; // 64K

// Nix daemon worker protocol magic numbers
const WORKER_MAGIC_1: u64 = 0x6e697863;
const WORKER_MAGIC_2: u64 = 0x6478696f;

// Protocol version constants
const PROTOCOL_VERSION_1_21: u64 = 0x11a; // Version 1.21
                                          // const PROTOCOL_VERSION_1_29: u64 = 0x11d; // Version 1.29 (for reference) - Unused
const CLIENT_VERSION: u64 = 0x126; // Version 1.38

#[derive(Debug, Clone, Copy)]
pub enum OpCode {
    IsValidPath = 1,
    QueryPathInfo = 4,
    QueryPathFromHashPart = 29,
    NarFromPath = 38,
    ImportPaths = 7,
}

#[derive(Debug, Clone)]
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

#[derive(Debug)]
pub struct NixDaemonProtocol {
    socket_path: String,
}

impl NixDaemonProtocol {
    pub fn new() -> Self {
        Self {
            socket_path: SOCKET_PATH.to_string(),
        }
    }

    pub fn with_socket_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            socket_path: path.as_ref().to_string_lossy().to_string(),
        }
    }

    pub async fn connect(&self) -> Result<UnixStream> {
        debug!("Connecting to Nix daemon at {}", self.socket_path);
        UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to Nix daemon")
    }

    // ============== CORE PROTOCOL OPERATIONS ==============

    async fn handshake(&mut self, stream: &mut UnixStream) -> Result<()> {
        debug!("Starting handshake with Nix daemon");

        // Write magic 1
        debug!("Sending worker magic: {:#x}", WORKER_MAGIC_1);
        write_u64(stream, WORKER_MAGIC_1).await?;

        // Read magic 2
        let magic = read_u64(stream).await?;
        if magic != WORKER_MAGIC_2 {
            bail!(
                "Invalid magic number from daemon: {:#x} (expected {:#x})",
                magic,
                WORKER_MAGIC_2
            );
        }

        // Read protocol version
        let protocol_version = read_u64(stream).await?;
        if protocol_version < PROTOCOL_VERSION_1_21 {
            bail!("Daemon protocol version too old: {:#x}", protocol_version);
        }

        // Write our version
        debug!("Sending client version: {:#x}", CLIENT_VERSION);
        write_u64(stream, CLIENT_VERSION).await?;

        // Write obsolete CPU affinity and reserved space
        write_u64(stream, 0).await?;
        write_u64(stream, 0).await?;

        // Exchange features if protocol >= 1.26
        if protocol_version >= 0x126 {
            let features = read_string_list(stream).await?;
            debug!("Server features: {:?}", features);
            write_string_list(stream, &[]).await?;
        }

        // Read server version and trusted flag
        let version = read_string(stream).await?;
        let trusted = read_u64(stream).await? == 1;
        debug!("Server version: {}, trusted: {}", version, trusted);

        // Process any initial stderr messages
        self.process_stderr(stream).await?;

        debug!("Handshake completed successfully");
        Ok(())
    }

    async fn process_stderr(&mut self, stream: &mut UnixStream) -> Result<()> {
        loop {
            let msg_type = read_u64(stream).await?;
            debug!("Stderr message type: {:#x}", msg_type);

            match msg_type {
                0x64617416 => {
                    // Write
                    let msg = read_string(stream).await?;
                    debug!("[nix-daemon] write: {}", msg);
                }
                0x63787470 => {
                    // Error
                    let err_type = read_string(stream).await?;
                    let level = read_u64(stream).await?;
                    let _name = read_string(stream).await?;
                    let message = read_string(stream).await?;
                    let _have_pos = read_u64(stream).await?;

                    let trace_count = read_u64(stream).await?;
                    for _ in 0..trace_count {
                        let _trace_have_pos = read_u64(stream).await?;
                        let _trace = read_string(stream).await?;
                    }

                    warn!(
                        "Daemon error: {} (type: {}, level: {})",
                        message, err_type, level
                    );
                    bail!("Daemon error: {}", message);
                }
                0x6f6c6d67 => {
                    // Next
                    let msg = read_string(stream).await?;
                    debug!("[nix-daemon] next: {}", msg);
                }
                0x53545254 => {
                    // StartActivity
                    let _act = read_u64(stream).await?;
                    let _lvl = read_u64(stream).await?;
                    let _typ = read_u64(stream).await?;
                    let msg = read_string(stream).await?;

                    let field_type = read_u64(stream).await?;
                    if field_type == 0 {
                        let _field = read_u64(stream).await?;
                    } else if field_type == 1 {
                        let _field = read_string(stream).await?;
                    } else {
                        bail!("Unknown field type: {}", field_type);
                    }

                    let _parent = read_u64(stream).await?;
                    debug!("[nix-daemon] start activity: {}", msg);
                }
                0x53544f50 => {
                    // StopActivity
                    let _act = read_u64(stream).await?;
                    debug!("[nix-daemon] stop activity");
                }
                0x52534c54 => {
                    // Result
                    let msg = read_string(stream).await?;
                    debug!("[nix-daemon] result: {}", msg);
                }
                0x616c7473 => {
                    // Last
                    debug!("[nix-daemon] last message");
                    return Ok(());
                }
                _ => {
                    bail!("Unknown stderr message type: {:#x}", msg_type);
                }
            }
        }
    }

    // ============== PUBLIC API METHODS ==============

    pub async fn is_valid_path(&mut self, path: &str) -> Result<bool> {
        debug!("Checking if path is valid: {}", path);

        let mut stream = self.connect().await?;
        self.handshake(&mut stream).await?;

        // Send operation
        write_u64(&mut stream, OpCode::IsValidPath as u64).await?;
        write_string(&mut stream, path).await?;

        // Process stderr
        self.process_stderr(&mut stream).await?;

        // Read result
        let valid = read_u64(&mut stream).await?;
        Ok(valid != 0)
    }

    pub async fn query_path_from_hash_part(&mut self, hash_part: &str) -> Result<Option<String>> {
        debug!("Looking up path for hash part: {}", hash_part);

        let mut stream = self.connect().await?;
        self.handshake(&mut stream).await?;

        // Send operation
        write_u64(&mut stream, OpCode::QueryPathFromHashPart as u64).await?;
        write_string(&mut stream, hash_part).await?;

        // Process stderr
        self.process_stderr(&mut stream).await?;

        // Read result
        let path = read_string(&mut stream).await?;
        if path.is_empty() {
            debug!("No path found for hash part: {}", hash_part);
            Ok(None)
        } else {
            debug!("Found path for hash part {}: {}", hash_part, path);
            Ok(Some(path))
        }
    }

    pub async fn query_path_info(&mut self, store_path: &str) -> Result<PathInfo> {
        debug!("Querying path info for: {}", store_path);

        let mut stream = self.connect().await?;
        self.handshake(&mut stream).await?;

        // Send operation
        write_u64(&mut stream, OpCode::QueryPathInfo as u64).await?;
        write_string(&mut stream, store_path).await?;

        // Process stderr
        self.process_stderr(&mut stream).await?;

        // Read exists flag
        let exists = read_u64(&mut stream).await?;
        if exists == 0 {
            bail!("Path not found: {}", store_path);
        }

        // Read path info
        let deriver = read_string(&mut stream).await?;
        let deriver = if deriver.is_empty() {
            None
        } else {
            Some(deriver)
        };

        let hash = read_string(&mut stream).await?;
        let nar_size = read_u64(&mut stream).await?;

        // Read references
        let ref_count = read_u64(&mut stream).await?;
        let mut references = Vec::with_capacity(ref_count as usize);
        for _ in 0..ref_count {
            references.push(read_string(&mut stream).await?);
        }

        // Read signatures
        let sig_count = read_u64(&mut stream).await?;
        let mut sigs = Vec::with_capacity(sig_count as usize);
        for _ in 0..sig_count {
            sigs.push(read_string(&mut stream).await?);
        }

        let registration_time = read_u64(&mut stream).await?;
        let ultimate = read_u64(&mut stream).await? != 0;

        // Read content address
        let has_ca = read_u64(&mut stream).await? != 0;
        let content_address = if has_ca {
            Some(read_string(&mut stream).await?)
        } else {
            None
        };

        Ok(PathInfo {
            deriver,
            hash,
            references,
            registration_time,
            nar_size,
            ultimate,
            sigs,
            content_address,
        })
    }

    pub async fn stream_nar<F>(&mut self, store_path: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(Bytes) -> Result<()>,
    {
        debug!("Streaming NAR for path: {}", store_path);

        let mut stream = self.connect().await?;
        self.handshake(&mut stream).await?;

        // Send operation
        write_u64(&mut stream, OpCode::NarFromPath as u64).await?;
        write_string(&mut stream, store_path).await?;

        // Process stderr
        self.process_stderr(&mut stream).await?;

        // Read chunks
        loop {
            let chunk_size = read_u64(&mut stream).await?;
            if chunk_size == 0 {
                break;
            }

            let mut chunk = vec![0u8; chunk_size as usize];
            stream.read_exact(&mut chunk).await?;

            callback(Bytes::from(chunk))?;
        }

        Ok(())
    }

    pub async fn import_nar(&mut self, nar_data: &[u8]) -> Result<String> {
        debug!("Importing NAR data ({} bytes)", nar_data.len());

        let mut stream = self.connect().await?;
        self.handshake(&mut stream).await?;

        // Send operation
        write_u64(&mut stream, OpCode::ImportPaths as u64).await?;
        write_u64(&mut stream, nar_data.len() as u64).await?;
        stream.write_all(nar_data).await?;

        // Process stderr
        self.process_stderr(&mut stream).await?;

        // Read number of paths
        let path_count = read_u64(&mut stream).await?;
        if path_count != 1 {
            bail!("Expected 1 imported path, got {}", path_count);
        }

        let path = read_string(&mut stream).await?;
        Ok(path)
    }
}

// ============== STANDALONE HELPER FUNCTIONS ==============

async fn read_u64(stream: &mut UnixStream) -> Result<u64> {
    let mut buf = [0u8; 8];
    stream
        .read_exact(&mut buf)
        .await
        .context("Failed to read u64")?;
    Ok(u64::from_be_bytes(buf))
}

async fn write_u64(stream: &mut UnixStream, value: u64) -> Result<()> {
    stream
        .write_all(&value.to_be_bytes())
        .await
        .context("Failed to write u64")?;
    Ok(())
}

async fn read_string(stream: &mut UnixStream) -> Result<String> {
    // Read length
    let len = read_u64(stream).await?;
    if len > MAX_STRING_SIZE {
        bail!("String too long: {} > {}", len, MAX_STRING_SIZE);
    }

    // Read content with padding
    let aligned_len = ((len + 7) / 8) * 8;
    let mut buf = vec![0u8; aligned_len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .context("Failed to read string content")?;

    // Convert to string
    let s = String::from_utf8(buf[..len as usize].to_vec())
        .context("Failed to parse string as UTF-8")?;

    Ok(s)
}

async fn write_string(stream: &mut UnixStream, s: &str) -> Result<()> {
    let bytes = s.as_bytes();

    // Write length
    write_u64(stream, bytes.len() as u64).await?;

    // Write content
    stream
        .write_all(bytes)
        .await
        .context("Failed to write string content")?;

    // Write padding
    let padding_size = ((bytes.len() + 7) / 8) * 8 - bytes.len();
    if padding_size > 0 {
        let padding = vec![0u8; padding_size];
        stream
            .write_all(&padding)
            .await
            .context("Failed to write string padding")?;
    }

    Ok(())
}

async fn read_string_list(stream: &mut UnixStream) -> Result<Vec<String>> {
    let len = read_u64(stream).await?;
    if len > MAX_STRING_LIST_SIZE {
        bail!("String list too long: {} > {}", len, MAX_STRING_LIST_SIZE);
    }

    let mut list = Vec::with_capacity(len as usize);
    for _ in 0..len {
        list.push(read_string(stream).await?);
    }

    Ok(list)
}

async fn write_string_list(stream: &mut UnixStream, list: &[String]) -> Result<()> {
    write_u64(stream, list.len() as u64).await?;

    for s in list {
        write_string(stream, s).await?;
    }

    Ok(())
}

// Implement Default trait
impl Default for NixDaemonProtocol {
    fn default() -> Self {
        Self::new()
    }
}
