use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::fmt;
use std::path::Path;
use std::str;
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
const MINIMUM_PROTOCOL_VERSION: u64 = 0x11a; // Version 1.21
const CLIENT_VERSION: u64 = 0x126; // Version 1.38

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum OpCode {
    IsValidPath = 1,
    HasSubstitutes = 3,
    QueryPathHash = 4,   // obsolete
    QueryReferences = 5, // obsolete
    QueryReferrers = 6,
    AddToStore = 7,
    AddTextToStore = 8, // obsolete since 1.25, Nix 3.0. Use WorkerProto::Op::AddToStore
    BuildPaths = 9,
    EnsurePath = 10,
    AddTempRoot = 11,
    AddIndirectRoot = 12,
    SyncWithGC = 13,
    FindRoots = 14,
    ExportPath = 16,   // obsolete
    QueryDeriver = 18, // obsolete
    SetOptions = 19,
    CollectGarbage = 20,
    QuerySubstitutablePathInfo = 21,
    QueryDerivationOutputs = 22, // obsolete
    QueryAllValidPaths = 23,
    QueryFailedPaths = 24,
    ClearFailedPaths = 25,
    QueryPathInfo = 26,
    ImportPaths = 27,                // obsolete
    QueryDerivationOutputNames = 28, // obsolete
    QueryPathFromHashPart = 29,
    QuerySubstitutablePathInfos = 30,
    QueryValidPaths = 31,
    QuerySubstitutablePaths = 32,
    QueryValidDerivers = 33,
    OptimiseStore = 34,
    VerifyStore = 35,
    BuildDerivation = 36,
    AddSignatures = 37,
    NarFromPath = 38,
    AddToStoreNar = 39,
    QueryMissing = 40,
    QueryDerivationOutputMap = 41,
    RegisterDrvOutput = 42,
    QueryRealisation = 43,
    AddMultipleToStore = 44,
    AddBuildLog = 45,
    BuildPathsWithResults = 46,
    AddPermRoot = 47,
}

#[derive(Debug)]
pub struct OpCodeError {
    code: u64,
}

impl fmt::Display for OpCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid OpCode: {}", self.code)
    }
}

impl std::error::Error for OpCodeError {}

impl TryFrom<u64> for OpCode {
    type Error = OpCodeError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::IsValidPath),
            3 => Ok(Self::HasSubstitutes),
            4 => Ok(Self::QueryPathHash),
            5 => Ok(Self::QueryReferences),
            6 => Ok(Self::QueryReferrers),
            7 => Ok(Self::AddToStore),
            8 => Ok(Self::AddTextToStore),
            9 => Ok(Self::BuildPaths),
            10 => Ok(Self::EnsurePath),
            11 => Ok(Self::AddTempRoot),
            12 => Ok(Self::AddIndirectRoot),
            13 => Ok(Self::SyncWithGC),
            14 => Ok(Self::FindRoots),
            16 => Ok(Self::ExportPath),
            18 => Ok(Self::QueryDeriver),
            19 => Ok(Self::SetOptions),
            20 => Ok(Self::CollectGarbage),
            21 => Ok(Self::QuerySubstitutablePathInfo),
            22 => Ok(Self::QueryDerivationOutputs),
            23 => Ok(Self::QueryAllValidPaths),
            24 => Ok(Self::QueryFailedPaths),
            25 => Ok(Self::ClearFailedPaths),
            26 => Ok(Self::QueryPathInfo),
            27 => Ok(Self::ImportPaths),
            28 => Ok(Self::QueryDerivationOutputNames),
            29 => Ok(Self::QueryPathFromHashPart),
            30 => Ok(Self::QuerySubstitutablePathInfos),
            31 => Ok(Self::QueryValidPaths),
            32 => Ok(Self::QuerySubstitutablePaths),
            33 => Ok(Self::QueryValidDerivers),
            34 => Ok(Self::OptimiseStore),
            35 => Ok(Self::VerifyStore),
            36 => Ok(Self::BuildDerivation),
            37 => Ok(Self::AddSignatures),
            38 => Ok(Self::NarFromPath),
            39 => Ok(Self::AddToStoreNar),
            40 => Ok(Self::QueryMissing),
            41 => Ok(Self::QueryDerivationOutputMap),
            42 => Ok(Self::RegisterDrvOutput),
            43 => Ok(Self::QueryRealisation),
            44 => Ok(Self::AddMultipleToStore),
            45 => Ok(Self::AddBuildLog),
            46 => Ok(Self::BuildPathsWithResults),
            47 => Ok(Self::AddPermRoot),
            _ => Err(OpCodeError { code: value }),
        }
    }
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

#[derive(Debug, PartialEq)]
#[allow(dead_code)]
enum Msg {
    Write = 0x64617416,
    Error = 0x63787470,
    Next = 0x6f6c6d67,
    StartActivity = 0x53545254,
    StopActivity = 0x53544f50,
    Result = 0x52534c54,
    Last = 0x616c7473,
}

#[derive(Debug)]
pub struct MsgCodeError {
    code: u64,
}

impl fmt::Display for MsgCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid Message code: {}", self.code)
    }
}

impl std::error::Error for MsgCodeError {}

impl TryFrom<u64> for Msg {
    type Error = MsgCodeError;

    fn try_from(value: u64) -> Result<Self, MsgCodeError> {
        match value {
            0x64617416 => Ok(Self::Write),
            0x63787470 => Ok(Self::Error),
            0x6f6c6d67 => Ok(Self::Next),
            0x53545254 => Ok(Self::StartActivity),
            0x53544f50 => Ok(Self::StopActivity),
            0x52534c54 => Ok(Self::Result),
            0x616c7473 => Ok(Self::Last),
            _ => Err(MsgCodeError { code: value }),
        }
    }
}

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

    async fn connect(&self) -> Result<UnixStream> {
        debug!("Connecting to Nix daemon at {}", self.socket_path);
        UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to Nix daemon")
    }

    async fn handshake(&mut self, socket: &mut UnixStream) -> Result<()> {
        // Write magic 1
        write_num(socket, WORKER_MAGIC_1).await?;

        // Read magic 2
        let magic = read_num::<u64>(socket).await?;
        if magic != WORKER_MAGIC_2 {
            bail!("Invalid magic number: {}", magic);
        }

        // Read protocol version
        let protocol_version = read_num::<u64>(socket).await?;
        if protocol_version < MINIMUM_PROTOCOL_VERSION {
            bail!("Protocol version mismatch: got {}", protocol_version);
        }

        // Write our version
        write_num::<u64>(socket, CLIENT_VERSION).await?;
        write_num(socket, 0u64).await?; // cpu affinity, obsolete
        write_num(socket, 0u64).await?; // reserve space, obsolete

        // Exchange features if protocol >= 1.26
        if protocol_version >= 0x126 {
            let features = read_string_list(socket).await?;
            debug!("Server features: {:?}", features);
            write_string_list(socket, &[]).await?;
        }

        // Read server version and trusted flag
        let version = read_string(socket).await?;
        let trusted = read_num::<u64>(socket).await? == 1;
        debug!("Server version: {}, trusted: {}", version, trusted);

        // Process any initial stderr messages
        self.process_stderr(socket).await?;

        debug!("Handshake completed successfully");
        Ok(())
    }

    async fn process_stderr(&mut self, socket: &mut UnixStream) -> Result<()> {
        loop {
            let msg_type = read_num::<u64>(socket).await?;

            match Msg::try_from(msg_type) {
                Ok(Msg::Write) => {
                    let msg = read_string(socket).await?;
                    debug!("[nix-daemon] write: {}", msg);
                }
                Ok(Msg::Error) => {
                    let err_type = read_string(socket).await?;
                    let level = read_num::<u64>(socket).await?;
                    let _name = read_string(socket).await?;
                    let message = read_string(socket).await?;
                    let _have_pos = read_num::<u64>(socket).await?;

                    let traces_len = read_num::<u64>(socket).await?;
                    for _ in 0..traces_len {
                        let _have_pos = read_num::<u64>(socket).await?;
                        let _trace = read_string(socket).await?;
                    }

                    warn!(
                        "Daemon error: {} (type: {}, level: {})",
                        message, err_type, level
                    );
                    bail!("Daemon error: {}", message);
                }
                Ok(Msg::Next) => {
                    let msg = read_string(socket).await?;
                    debug!("[nix-daemon] next: {}", msg);
                }
                Ok(Msg::StartActivity) => {
                    let _act = read_num::<u64>(socket).await?;
                    let _lvl = read_num::<u64>(socket).await?;
                    let _typ = read_num::<u64>(socket).await?;
                    let msg = read_string(socket).await?;

                    let field_type = read_num::<u64>(socket).await?;
                    if field_type == 0 {
                        let _field = read_num::<u64>(socket).await?;
                    } else if field_type == 1 {
                        let _field = read_string(socket).await?;
                    } else {
                        bail!("Unknown field type: {}", field_type);
                    }

                    let _parent = read_num::<u64>(socket).await?;
                    debug!("[nix-daemon] start activity: {}", msg);
                }
                Ok(Msg::StopActivity) => {
                    let _act = read_num::<u64>(socket).await?;
                    debug!("[nix-daemon] stop activity");
                }
                Ok(Msg::Result) => {
                    let msg = read_string(socket).await?;
                    debug!("[nix-daemon] result: {}", msg);
                }
                Ok(Msg::Last) => {
                    debug!("[nix-daemon] last message");
                    return Ok(());
                }
                Err(e) => {
                    bail!("Unknown stderr message type: {} - {}", msg_type, e);
                }
            }
        }
    }

    pub async fn is_valid_path(&mut self, path: &str) -> Result<bool> {
        debug!("Checking if path is valid: {}", path);

        let mut socket = self.connect().await?;
        self.handshake(&mut socket).await?;

        // Send operation
        write_num(&mut socket, OpCode::IsValidPath as u64).await?;
        write_string(&mut socket, path).await?;

        // Process stderr
        self.process_stderr(&mut socket).await?;

        // Read result
        let valid = read_num::<u64>(&mut socket).await?;
        Ok(valid != 0)
    }

    pub async fn query_path_from_hash_part(&mut self, hash_part: &str) -> Result<Option<String>> {
        debug!("Looking up path for hash part: {}", hash_part);

        let mut socket = self.connect().await?;
        self.handshake(&mut socket).await?;

        // Send operation
        write_num(&mut socket, OpCode::QueryPathFromHashPart as u64).await?;
        write_string(&mut socket, hash_part).await?;

        // Process stderr
        self.process_stderr(&mut socket).await?;

        // Read result
        let path = read_string(&mut socket).await?;
        if path.is_empty() {
            debug!("No path found for hash part: {}", hash_part);
            Ok(None)
        } else {
            debug!("Found path for hash part {}: {}", hash_part, path);
            Ok(Some(path))
        }
    }

    pub async fn query_path_info(&mut self, path: &str) -> Result<PathInfo> {
        debug!("Querying path info for: {}", path);

        let mut socket = self.connect().await?;
        self.handshake(&mut socket).await?;

        // Send operation
        write_num(&mut socket, OpCode::QueryPathInfo as u64).await?;
        write_string(&mut socket, path).await?;

        // Process stderr
        self.process_stderr(&mut socket).await?;

        // Read exists flag
        let exists = read_num::<u64>(&mut socket).await?;
        if exists == 0 {
            bail!("Path not found: {}", path);
        }

        // Read path info
        let deriver = read_string(&mut socket).await?;
        let deriver = if deriver.is_empty() {
            None
        } else {
            Some(deriver)
        };

        let hash = read_string(&mut socket).await?;
        let references = read_string_list(&mut socket).await?;
        let registration_time = read_num::<u64>(&mut socket).await?;
        let nar_size = read_num::<u64>(&mut socket).await?;
        let ultimate = read_num::<u64>(&mut socket).await? != 0;
        let sigs = read_string_list(&mut socket).await?;

        // Read content address (may be an empty string)
        let ca = read_string(&mut socket).await?;
        let content_address = if ca.is_empty() { None } else { Some(ca) };

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

    pub async fn add_to_store_nar(&mut self, nar_data: &[u8], name: &str) -> Result<String> {
        debug!(
            "Adding NAR to store (name: {}, size: {} bytes)",
            name,
            nar_data.len()
        );

        let mut socket = self.connect().await?;
        self.handshake(&mut socket).await?;

        // Send operation
        write_num(&mut socket, OpCode::AddToStoreNar as u64).await?;

        // The protocol for AddToStoreNar:

        // Base name to use
        write_string(&mut socket, name).await?;

        // Flags: 0 = no repair
        write_num(&mut socket, 0u64).await?;

        // Whether to repair: false (0)
        write_num(&mut socket, 0u64).await?;

        // NAR size
        write_num(&mut socket, nar_data.len() as u64).await?;

        // NAR data
        socket.write_all(nar_data).await?;

        // Process stderr
        self.process_stderr(&mut socket).await?;

        // Read result (store path)
        let path = read_string(&mut socket).await?;
        debug!("Successfully added NAR to store at path: {}", path);

        Ok(path)
    }

    pub async fn stream_nar<F>(&mut self, store_path: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(Bytes) -> Result<()>,
    {
        debug!("Streaming NAR for path: {}", store_path);

        let mut socket = self.connect().await?;
        self.handshake(&mut socket).await?;

        // Send operation
        write_num(&mut socket, OpCode::NarFromPath as u64).await?;
        write_string(&mut socket, store_path).await?;

        // Process stderr
        self.process_stderr(&mut socket).await?;

        // Read chunks
        loop {
            let chunk_size = read_num::<u64>(&mut socket).await?;
            if chunk_size == 0 {
                break;
            }

            let mut chunk = vec![0u8; chunk_size as usize];
            socket.read_exact(&mut chunk).await?;

            callback(Bytes::from(chunk))?;
        }

        Ok(())
    }
}

// Helper functions
async fn read_num<T: From<u64>>(socket: &mut UnixStream) -> Result<T> {
    let mut buf = [0; 8];
    socket
        .read_exact(&mut buf)
        .await
        .context("Failed to read number")?;
    Ok(T::from(u64::from_le_bytes(buf)))
}

async fn write_num<T: Into<u64>>(socket: &mut UnixStream, num: T) -> Result<()> {
    let num = num.into();
    socket
        .write_all(&num.to_le_bytes())
        .await
        .context("Failed to write number")
}

async fn read_string(socket: &mut UnixStream) -> Result<String> {
    let len = read_num::<u64>(socket).await?;
    if len > MAX_STRING_SIZE {
        bail!("String too long: {} > {}", len, MAX_STRING_SIZE);
    }

    let aligned_len = (len + 7) & !7; // Align to the next multiple of 8
    let mut buf = vec![0; aligned_len as usize];
    socket
        .read_exact(&mut buf)
        .await
        .context("Failed to read string")?;

    Ok(str::from_utf8(&buf[..len as usize])
        .context("Failed to parse string as UTF-8")?
        .to_owned())
}

async fn write_string(socket: &mut UnixStream, s: &str) -> Result<()> {
    let bytes = s.as_bytes();

    // Write length
    write_num::<u64>(socket, bytes.len() as u64).await?;

    // Write content
    socket
        .write_all(bytes)
        .await
        .context("Failed to write string content")?;

    // Write padding
    let padding_size = (8 - bytes.len() % 8) % 8;
    if padding_size > 0 {
        let padding = vec![0u8; padding_size];
        socket
            .write_all(&padding)
            .await
            .context("Failed to write string padding")?;
    }

    Ok(())
}

async fn read_string_list(socket: &mut UnixStream) -> Result<Vec<String>> {
    let len = read_num::<u64>(socket).await?;
    if len > MAX_STRING_LIST_SIZE {
        bail!("String list too long: {} > {}", len, MAX_STRING_LIST_SIZE);
    }

    let mut list = Vec::with_capacity(len as usize);
    for _ in 0..len {
        list.push(read_string(socket).await?);
    }

    Ok(list)
}

async fn write_string_list(socket: &mut UnixStream, list: &[String]) -> Result<()> {
    write_num::<u64>(socket, list.len() as u64).await?;

    for s in list {
        write_string(socket, s).await?;
    }

    Ok(())
}

// Default implementation
impl Default for NixDaemonProtocol {
    fn default() -> Self {
        Self::new()
    }
}
