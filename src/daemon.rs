use anyhow::{bail, Context, Result};
use std::fmt;
use std::str;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use tracing::{debug, warn};

const SOCKET_PATH: &str = "/nix/var/nix/daemon-socket/socket";

// Tailles maximales pour les chaînes et listes
const MAX_STRING_SIZE: u64 = 0x1000000; // 16MB
const MAX_STRING_LIST_SIZE: u64 = 0x10000; // 64K

// Constantes pour l'handshake avec le démon
const WORKER_MAGIC_1: u64 = 0x6e697863;
const WORKER_MAGIC_2: u64 = 0x6478696f;

// Version minimale du protocole requise
const MINIMUM_PROTOCOL_VERSION: u64 = 0x11a; // Version 1.21
                                             // Version du client que nous prétendons être
const CLIENT_VERSION: u64 = 0x126; // Version 1.38

// Opcodes pour les commandes au démon
#[derive(Debug, Clone, Copy)]
enum OpCode {
    IsValidPath = 1,
    HasSubstitutes = 3,
    QueryPathHash = 4,   // obsolète
    QueryReferences = 5, // obsolète
    QueryReferrers = 6,
    AddToStore = 7,
    AddTextToStore = 8, // obsolète depuis 1.25, Nix 3.0. Utiliser WorkerProto::Op::AddToStore
    BuildPaths = 9,
    EnsurePath = 10,
    AddTempRoot = 11,
    AddIndirectRoot = 12,
    SyncWithGC = 13,
    FindRoots = 14,
    ExportPath = 16,   // obsolète
    QueryDeriver = 18, // obsolète
    SetOptions = 19,
    CollectGarbage = 20,
    QuerySubstitutablePathInfo = 21,
    QueryDerivationOutputs = 22, // obsolète
    QueryAllValidPaths = 23,
    QueryFailedPaths = 24,
    ClearFailedPaths = 25,
    QueryPathInfo = 26,
    ImportPaths = 27,                // obsolète
    QueryDerivationOutputNames = 28, // obsolète
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
struct OpCodeError {
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

// Types de messages du démon
#[derive(Debug, Clone, Copy, PartialEq)]
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
struct MsgCodeError {
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

#[derive(Debug, Clone, PartialEq)]
pub struct ValidPathInfo {
    pub deriver: String,
    pub hash: String,
    pub references: Vec<String>,
    pub registration_time: u64,
    pub nar_size: u64,
    pub ultimate: bool,
    pub sigs: Vec<String>,
    pub content_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueryPathInfoResponse {
    pub path: Option<ValidPathInfo>,
}

// Structure pour communiquer avec le démon
#[derive(Debug, Default)]
pub struct DaemonConnection {
    socket: Option<UnixStream>,
    #[allow(dead_code)]
    server_features: Vec<String>,
    #[allow(dead_code)]
    daemon_version: String,
    #[allow(dead_code)]
    is_trusted: bool,
}

// Définir HandshakeData au niveau du module, à l'extérieur de l'implémentation
#[derive(Debug)]
struct HandshakeData {
    server_features: Vec<String>,
    daemon_version: String,
    is_trusted: bool,
}

// Fonctions utilitaires pour la communication avec le socket
async fn write_num<T: Into<u64>>(socket: &mut UnixStream, num: T) -> Result<()> {
    let num = num.into();
    socket
        .write_all(&num.to_le_bytes())
        .await
        .context("Failed to write number to socket")
}

async fn read_num<T: From<u64>>(socket: &mut UnixStream) -> Result<T> {
    let mut buf = [0; 8];
    socket
        .read_exact(&mut buf)
        .await
        .context("Failed to read number from socket")?;
    Ok(T::from(u64::from_le_bytes(buf)))
}

async fn write_string(socket: &mut UnixStream, s: &str) -> Result<()> {
    write_num::<u64>(socket, s.len() as u64).await?;
    socket.write_all(s.as_bytes()).await?;

    // Padding pour aligner sur 8 octets
    let padding_size = (8 - s.len() % 8) % 8;
    if padding_size > 0 {
        let padding = [0u8; 8];
        socket.write_all(&padding[0..padding_size]).await?;
    }

    Ok(())
}

async fn read_string(socket: &mut UnixStream) -> Result<String> {
    let len = read_num::<u64>(socket)
        .await
        .context("Failed to read string length")?;

    if len > MAX_STRING_SIZE {
        bail!("String too long: {} > {}", len, MAX_STRING_SIZE);
    }

    let aligned_len = (len + 7) & !7; // Aligner sur un multiple de 8
    let mut buf = vec![0; aligned_len as usize];

    socket
        .read_exact(&mut buf)
        .await
        .context("Failed to read string data")?;

    Ok(str::from_utf8(&buf[..len as usize])
        .context("Failed to parse string as UTF-8")?
        .to_owned())
}

async fn read_string_list(socket: &mut UnixStream) -> Result<Vec<String>> {
    let len = read_num::<u64>(socket).await?;

    if len > MAX_STRING_LIST_SIZE {
        bail!("String list too long: {} > {}", len, MAX_STRING_LIST_SIZE);
    }

    let mut result = Vec::with_capacity(len as usize);
    for _ in 0..len {
        result.push(read_string(socket).await?);
    }

    Ok(result)
}

async fn write_string_list(socket: &mut UnixStream, list: &[String]) -> Result<()> {
    write_num::<u64>(socket, list.len() as u64).await?;

    for s in list {
        write_string(socket, s).await?;
    }

    Ok(())
}

// Traiter les messages d'erreur et de statut du démon (version statique)
async fn process_daemon_messages(socket: &mut UnixStream) -> Result<()> {
    loop {
        let msg_code = read_num::<u64>(socket)
            .await
            .context("Failed to read message code")?;

        match Msg::try_from(msg_code) {
            Ok(Msg::Write) => {
                let msg = read_string(socket).await?;
                debug!("[nix-daemon] write: {}", msg);
            }
            Ok(Msg::Error) => {
                let err_type = read_string(socket)
                    .await
                    .context("Failed to read error type")?;
                let level = read_num::<u64>(socket)
                    .await
                    .context("Failed to read error level")?;
                let _name = read_string(socket)
                    .await
                    .context("Failed to read error name")?;
                let message = read_string(socket)
                    .await
                    .context("Failed to read error message")?;
                let _have_pos = read_num::<u64>(socket)
                    .await
                    .context("Failed to read error position flag")?;

                let traces_len = read_num::<u64>(socket)
                    .await
                    .context("Failed to read number of traces")?;
                for _ in 0..traces_len {
                    let _have_pos = read_num::<u64>(socket)
                        .await
                        .context("Failed to read trace position flag")?;
                    let _trace = read_string(socket).await.context("Failed to read trace")?;
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
                let s = read_string(socket).await?;

                let field_type = read_num::<u64>(socket).await?;
                if field_type == 0 {
                    let _field = read_num::<u64>(socket).await?;
                } else if field_type == 1 {
                    let _field = read_string(socket).await?;
                } else {
                    bail!("Unknown field type: {}", field_type);
                }

                let _parent = read_num::<u64>(socket).await?;

                debug!("[nix-daemon] start activity: {}", s);
            }
            Ok(Msg::StopActivity) => {
                let _act = read_num::<u64>(socket).await?;
                debug!("[nix-daemon] stop activity");
            }
            Ok(Msg::Result) => {
                let res = read_string(socket).await?;
                debug!("[nix-daemon] result: {}", res);
            }
            Ok(Msg::Last) => {
                debug!("[nix-daemon] last message");
                return Ok(());
            }
            Err(e) => {
                bail!("Unknown stderr message type: {} - {}", msg_code, e);
            }
        }
    }
}

impl DaemonConnection {
    // Établir ou réutiliser une connexion
    async fn connect(&mut self) -> Result<&mut UnixStream> {
        if let Some(ref mut socket) = self.socket {
            return Ok(socket);
        }

        debug!("Connecting to Nix daemon at {}", SOCKET_PATH);
        let mut socket = UnixStream::connect(SOCKET_PATH)
            .await
            .context("Failed to connect to Nix daemon")?;

        // Effectuer le handshake
        let handshake = self.handshake(&mut socket).await?;

        self.server_features = handshake.server_features;
        self.daemon_version = handshake.daemon_version;
        self.is_trusted = handshake.is_trusted;

        self.socket = Some(socket);
        Ok(self.socket.as_mut().unwrap())
    }

    // Handshake avec le démon
    async fn handshake(&mut self, socket: &mut UnixStream) -> Result<HandshakeData> {
        // Écrire le premier magic number
        write_num(socket, WORKER_MAGIC_1).await?;

        // Lire le second magic number
        let magic = read_num::<u64>(socket).await?;
        if magic != WORKER_MAGIC_2 {
            bail!("Invalid magic number from daemon: {}", magic);
        }

        // Lire la version du protocole
        let protocol_version = read_num::<u64>(socket).await?;
        if protocol_version < MINIMUM_PROTOCOL_VERSION {
            bail!("Protocol version too old: {}", protocol_version);
        }

        // Écrire notre version
        write_num::<u64>(socket, CLIENT_VERSION).await?;
        write_num(socket, 0u64).await?; // cpu affinity (obsolète)
        write_num(socket, 0u64).await?; // reserve space (obsolète)

        // Échange de fonctionnalités si la version du protocole le permet
        let server_features = if protocol_version >= 0x126 {
            let features = read_string_list(socket).await?;
            debug!("Server features: {:?}", features);
            write_string_list(socket, &[]).await?;
            features
        } else {
            Vec::new()
        };

        // Lire la version du serveur et le flag de confiance
        let daemon_version = read_string(socket).await?;
        let is_trusted = read_num::<u64>(socket).await? == 1;
        debug!(
            "Server version: {}, trusted: {}",
            daemon_version, is_trusted
        );

        // Traiter les messages stderr initiaux
        process_daemon_messages(socket).await?;

        debug!("Handshake completed successfully");

        Ok(HandshakeData {
            server_features,
            daemon_version,
            is_trusted,
        })
    }

    // Envoyer une opération au démon
    async fn send_op(&mut self, op: OpCode) -> Result<()> {
        let socket = self.connect().await?;
        write_num(socket, op as u64)
            .await
            .context(format!("Failed to send opcode {:?}", op))?;
        Ok(())
    }

    // Vérifier si un chemin est valide
    pub async fn is_valid_path(&mut self, path: &str) -> Result<bool> {
        debug!("Checking if path is valid: {}", path);

        self.send_op(OpCode::IsValidPath).await?;

        let socket = self.connect().await?;
        write_string(socket, path)
            .await
            .context("Failed to write path")?;

        // Utiliser la fonction statique au lieu de la méthode
        process_daemon_messages(socket).await?;

        let valid = read_num::<u64>(socket)
            .await
            .context("Failed to read result")?;

        debug!("Path {} is valid: {}", path, valid != 0);
        Ok(valid != 0)
    }

    // Obtenir un chemin à partir d'une partie du hash
    pub async fn query_path_from_hash_part(&mut self, hash_part: &str) -> Result<Option<String>> {
        debug!("Looking up path for hash part: {}", hash_part);

        self.send_op(OpCode::QueryPathFromHashPart).await?;

        let socket = self.connect().await?;
        write_string(socket, hash_part)
            .await
            .context("Failed to write hash part")?;

        // Utiliser la fonction statique
        process_daemon_messages(socket).await?;

        let path = read_string(socket).await.context("Failed to read path")?;

        if path.is_empty() {
            debug!("No path found for hash part: {}", hash_part);
            Ok(None)
        } else {
            debug!("Found path for hash part {}: {}", hash_part, path);
            Ok(Some(path))
        }
    }

    // Obtenir les informations sur un chemin
    pub async fn query_path_info(&mut self, path: &str) -> Result<QueryPathInfoResponse> {
        debug!("Querying path info for: {}", path);

        self.send_op(OpCode::QueryPathInfo).await?;

        let socket = self.connect().await?;
        write_string(socket, path)
            .await
            .context("Failed to write path")?;

        // Utiliser la fonction statique
        process_daemon_messages(socket).await?;

        // Lire le flag d'existence
        let exists = read_num::<u64>(socket)
            .await
            .context("Failed to read exists flag")?;

        if exists == 0 {
            debug!("Path not found: {}", path);
            return Ok(QueryPathInfoResponse { path: None });
        }

        // Lire les informations sur le chemin
        let deriver = read_string(socket)
            .await
            .context("Failed to read deriver")?;
        let hash = read_string(socket).await.context("Failed to read hash")?;
        let references = read_string_list(socket)
            .await
            .context("Failed to read references")?;
        let registration_time = read_num::<u64>(socket)
            .await
            .context("Failed to read registration time")?;
        let nar_size = read_num::<u64>(socket)
            .await
            .context("Failed to read NAR size")?;
        let ultimate = read_num::<u64>(socket)
            .await
            .context("Failed to read ultimate flag")?
            != 0;
        let sigs = read_string_list(socket)
            .await
            .context("Failed to read signatures")?;

        // Lire l'adresse de contenu (peut être vide)
        let ca = read_string(socket)
            .await
            .context("Failed to read content address")?;
        let content_address = if ca.is_empty() { None } else { Some(ca) };

        debug!("Got path info for {}", path);

        Ok(QueryPathInfoResponse {
            path: Some(ValidPathInfo {
                deriver,
                hash,
                references,
                registration_time,
                nar_size,
                ultimate,
                sigs,
                content_address,
            }),
        })
    }

    // Streamer un NAR à partir d'un chemin
    pub async fn stream_nar<F>(&mut self, store_path: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> Result<()>,
    {
        debug!("Streaming NAR for path: {}", store_path);

        self.send_op(OpCode::NarFromPath).await?;

        let socket = self.connect().await?;
        write_string(socket, store_path)
            .await
            .context("Failed to write store path")?;

        // Utiliser la fonction statique
        process_daemon_messages(socket).await?;

        // Lire les chunks de données
        loop {
            let chunk_size = read_num::<u64>(socket)
                .await
                .context("Failed to read chunk size")?;

            if chunk_size == 0 {
                debug!("End of NAR stream");
                break;
            }

            let mut chunk = vec![0u8; chunk_size as usize];
            socket
                .read_exact(&mut chunk)
                .await
                .context("Failed to read chunk data")?;

            callback(chunk)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    #[tokio::test]
    async fn test_nix_daemon_connection() -> Result<()> {
        // Skip test if socket doesn't exist (e.g. in CI environment)
        if !Path::new(SOCKET_PATH).exists() {
            return Ok(());
        }

        let mut conn = DaemonConnection::default();

        // Test store path
        let temp_dir = tempfile::tempdir().context("Failed to create temp dir")?;
        let temp_path = temp_dir.path().join("test.txt");
        std::fs::write(&temp_path, b"hello world").context("Failed to write test file")?;

        let output = Command::new("nix-store")
            .arg("--add")
            .arg(&temp_path)
            .output()
            .context("Failed to add file to store")?;

        let store_path = std::str::from_utf8(&output.stdout)
            .context("Failed to parse store path")?
            .trim()
            .to_owned();

        // Verify the path is valid
        assert!(
            conn.is_valid_path(&store_path).await?,
            "Path should be valid"
        );

        // Query path info
        let path_info = conn
            .query_path_info(&store_path)
            .await?
            .path
            .expect("Path info should exist");

        assert!(!path_info.hash.is_empty(), "Hash should not be empty");
        assert!(path_info.nar_size > 0, "NAR size should be positive");

        // Extract hash part from store path
        let hash_part = store_path
            .strip_prefix("/nix/store/")
            .unwrap_or(&store_path)
            .split('-')
            .next()
            .unwrap_or("");

        // Query path from hash part
        let lookup_path = conn
            .query_path_from_hash_part(hash_part)
            .await?
            .expect("Path should be found");

        assert_eq!(lookup_path, store_path, "Paths should match");

        Ok(())
    }
}
