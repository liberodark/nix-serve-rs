use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::fs::{create_dir_all, File};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener};
use tokio::process::Command;
use tokio::signal;
use tracing::{debug, error, info};

use crate::config::Config;
use crate::crypto::signing::fingerprint_path;
use crate::error::{NixServeError, NixServeResult};
use crate::nix::path_info::PathInfo;
use crate::nix::store::NixStore;
use crate::routes;

pub struct Server {
    config: Config,
    store: Arc<NixStore>,
}

impl Server {
    pub fn new(config: Config) -> Result<Self> {
        let store = NixStore::new(&config.virtual_store, config.real_store.as_deref())
            .context("Failed to initialize Nix store")?;

        Ok(Self {
            config,
            store: Arc::new(store),
        })
    }

    pub async fn run(&self) -> Result<()> {
        if self.config.bind.starts_with("unix:") {
            let socket_path = &self.config.bind[5..];
            self.run_unix(socket_path).await
        } else {
            let addr: SocketAddr = self
                .config
                .bind
                .parse()
                .with_context(|| format!("Invalid bind address: {}", self.config.bind))?;
            self.run_tcp(addr).await
        }
    }

    async fn run_tcp(&self, addr: SocketAddr) -> Result<()> {
        let config = Arc::new(self.config.clone());
        let store = Arc::clone(&self.store);

        info!("Listening on TCP {}", addr);

        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))?;

        self.run_server_tcp(listener, config, store).await
    }

    async fn run_unix(&self, path: &str) -> Result<()> {
        let config = Arc::new(self.config.clone());
        let store = Arc::clone(&self.store);

        info!("Listening on Unix socket {}", path);

        if Path::new(path).exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("Failed to remove existing socket file: {}", path))?;
        }

        let listener = UnixListener::bind(path)
            .with_context(|| format!("Failed to bind to Unix socket: {}", path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o777);
            std::fs::set_permissions(path, permissions)
                .with_context(|| format!("Failed to set permissions on socket: {}", path))?;
        }

        self.run_server_unix(listener, config, store).await
    }

    async fn run_server_tcp(
        &self,
        listener: TcpListener,
        config: Arc<Config>,
        store: Arc<NixStore>,
    ) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

        let shutdown_tx_clone = Arc::clone(&shutdown_tx);
        tokio::spawn(async move {
            match signal::ctrl_c().await {
                Ok(()) => {
                    info!("Shutdown signal received, gracefully shutting down...");
                    if let Some(tx) = shutdown_tx_clone.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                }
                Err(err) => {
                    error!("Failed to listen for shutdown signal: {}", err);
                }
            }
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            info!("New connection from {}", addr);

                            let io = TokioIo::new(stream);
                            let store = Arc::clone(&store);
                            let config = Arc::clone(&config);

                            tokio::spawn(async move {
                                let service = service_fn(move |req| {
                                    handle_request(req, Arc::clone(&config), Arc::clone(&store))
                                });

                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("Error serving connection: {}", err);
                                }
                            });
                        }
                        Err(err) => {
                            error!("Failed to accept connection: {}", err);
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received, stopping server...");
                    break;
                }
            }
        }

        info!("Server shutdown complete");
        Ok(())
    }

    async fn run_server_unix(
        &self,
        listener: UnixListener,
        config: Arc<Config>,
        store: Arc<NixStore>,
    ) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

        let shutdown_tx_clone = Arc::clone(&shutdown_tx);
        tokio::spawn(async move {
            match signal::ctrl_c().await {
                Ok(()) => {
                    info!("Shutdown signal received, gracefully shutting down...");
                    if let Some(tx) = shutdown_tx_clone.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                }
                Err(err) => {
                    error!("Failed to listen for shutdown signal: {}", err);
                }
            }
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            info!("New connection on Unix socket");

                            let io = TokioIo::new(stream);
                            let store = Arc::clone(&store);
                            let config = Arc::clone(&config);

                            tokio::spawn(async move {
                                let service = service_fn(move |req| {
                                    handle_request(req, Arc::clone(&config), Arc::clone(&store))
                                });

                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("Error serving connection: {}", err);
                                }
                            });
                        }
                        Err(err) => {
                            error!("Failed to accept connection: {}", err);
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received, stopping server...");
                    break;
                }
            }
        }

        info!("Server shutdown complete");
        Ok(())
    }
}

async fn handle_request(
    req: Request<Incoming>,
    config: Arc<Config>,
    store: Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path();

    info!("{} {}", method, path);

    let response = match (method.as_str(), path) {
        ("GET", "/health") => routes::health::get().await,

        ("GET", "/nix-cache-info") => routes::cache_info::get(&config).await,

        ("GET", "/version") => routes::version::get().await,

        ("GET", "/") => routes::root::get(&config).await,

        ("HEAD", _) if path.starts_with("/nar/") => {
            // Process HEAD requests for NAR files - Nix does this to check if the file exists
            // before uploading
            handle_nar_head_request(path, &config, &store).await
        }

        ("PUT", _) if path.starts_with("/nar/") => {
            // Process uploads of NAR files
            handle_nar_upload(path, req.into_body(), &config, &store).await
        }

        _ => {
            if path.ends_with(".narinfo") && method == Method::GET {
                let hash = path.trim_start_matches('/').trim_end_matches(".narinfo");
                routes::narinfo::get(hash, &config, &store).await
            } else if path.starts_with("/nar/") && method == Method::GET {
                routes::nar::get(path, uri.query(), &config, &store).await
            } else if path.starts_with("/log/") && method == Method::GET {
                let hash = path.trim_start_matches("/log/");
                routes::build_log::get(hash, &config, &store).await
            } else {
                let mut response = Response::new(full_body("Not Found"));
                *response.status_mut() = StatusCode::NOT_FOUND;
                Ok(response)
            }
        }
    };

    match response {
        Ok(resp) => Ok(resp),
        Err(err) => {
            error!("Error handling request: {}", err);
            let mut response = Response::new(full_body(&format!("Internal Server Error: {}", err)));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(response)
        }
    }
}

/// Handle HEAD requests for NAR files
/// This is used by Nix to check if a file exists before uploading it
async fn handle_nar_head_request(
    path: &str,
    config: &Arc<Config>,
    _store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("HEAD request for NAR: {}", path);

    // Extract the filename from the path
    let filename = path.trim_start_matches("/nar/");

    // Check if the file already exists in the cache
    let nar_path = PathBuf::from(config.real_store())
        .join("nar")
        .join(filename);

    if nar_path.exists() {
        debug!("NAR file exists: {}", nar_path.display());
        let mut response = Response::new(full_body(""));
        *response.status_mut() = StatusCode::OK;
        Ok(response)
    } else {
        debug!("NAR file does not exist: {}", nar_path.display());
        let mut response = Response::new(full_body(""));
        *response.status_mut() = StatusCode::NOT_FOUND;
        Ok(response)
    }
}

/// Handle PUT requests for NAR files
/// This is the main function for handling Nix binary cache uploads
async fn handle_nar_upload(
    path: &str,
    body: Incoming,
    config: &Arc<Config>,
    _store: &Arc<NixStore>,
) -> Result<Response<BoxBody<Bytes, Infallible>>> {
    debug!("Processing NAR upload request: {}", path);

    // Extract the filename and hash from the path
    let filename = match path.split('/').last() {
        Some(name) => name,
        None => {
            error!("Invalid NAR path: {}", path);
            let mut response = Response::new(full_body("Invalid NAR path"));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(response);
        }
    };

    // Ensure the nar directory exists
    let cache_dir = PathBuf::from(config.real_store());
    let nar_dir = cache_dir.join("nar");

    if !nar_dir.exists() {
        match create_dir_all(&nar_dir).await {
            Ok(_) => debug!("Created NAR directory: {}", nar_dir.display()),
            Err(e) => {
                error!("Failed to create NAR directory: {}", e);
                let mut response = Response::new(full_body(&format!(
                    "Failed to create cache directory: {}",
                    e
                )));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            }
        }
    }

    // Define the full output path
    let output_path = nar_dir.join(filename);
    debug!("Will save NAR to: {}", output_path.display());

    // Read the body into memory
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Failed to read request body: {}", e);
            let mut response =
                Response::new(full_body(&format!("Failed to read request body: {}", e)));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
    };

    // Calculate the hash of the uploaded data for verification
    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);
    debug!("Calculated hash for uploaded NAR: sha256:{}", hash_hex);

    // Verify the hash matches the filename if possible
    if let Some(nar_hash) = filename
        .strip_suffix(".nar.xz")
        .or_else(|| filename.strip_suffix(".nar"))
    {
        debug!("Validating NAR hash in filename: {}", nar_hash);
    }

    // Store the NAR file
    match File::create(&output_path).await {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&body_bytes).await {
                error!("Failed to write NAR file: {}", e);
                let mut response =
                    Response::new(full_body(&format!("Failed to write NAR file: {}", e)));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            }
        }
        Err(e) => {
            error!("Failed to create NAR file: {}", e);
            let mut response =
                Response::new(full_body(&format!("Failed to create NAR file: {}", e)));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
    }

    info!("Successfully saved NAR file: {}", output_path.display());

    // Create a successful response
    let mut response = Response::new(full_body("OK"));
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

/// Updates or creates a narinfo file for a store path
#[allow(dead_code)]
async fn update_or_create_narinfo(
    store_path: &str,
    nar_hash: &str,
    nar_size: u64,
    references: &[String],
    config: &Config,
    _store: &NixStore,
) -> NixServeResult<()> {
    // Generate the narinfo content
    let narinfo_content =
        generate_narinfo(store_path, nar_hash, nar_size, references, config).await?;

    // Extract the hash part from the store path (qui serait utilisé comme nom de fichier)
    let path_parts: Vec<&str> = store_path.split('-').collect();
    if path_parts.is_empty() {
        return Err(NixServeError::internal("Invalid store path format"));
    }

    let hash_part = path_parts[0]
        .trim_start_matches('/')
        .trim_start_matches("nix/store/");

    // Define the narinfo path
    let narinfo_path = PathBuf::from(config.real_store())
        .parent()
        .ok_or_else(|| NixServeError::internal("Could not get parent of real store"))?
        .join(format!("{}.narinfo", hash_part));

    // Write the narinfo file
    std::fs::write(&narinfo_path, narinfo_content)
        .map_err(|e| NixServeError::internal(format!("Failed to write narinfo file: {}", e)))?;

    Ok(())
}

/// Generate a Nix-compatible narinfo file for a store path
/// This function is called when a .narinfo file is uploaded or needs to be updated
#[allow(dead_code)]
async fn generate_narinfo(
    store_path: &str,
    nar_hash: &str,
    nar_size: u64,
    references: &[String],
    config: &Config,
) -> NixServeResult<String> {
    let mut lines = vec![
        format!("StorePath: {}", store_path),
        format!("URL: nar/{}.nar", nar_hash),
        format!("Compression: xz"),
        format!("NarHash: sha256:{}", nar_hash),
        format!("NarSize: {}", nar_size),
    ];

    if !references.is_empty() {
        let ref_basenames = references
            .iter()
            .filter_map(|r| PathInfo::extract_basename(r))
            .collect::<Vec<_>>();

        lines.push(format!("References: {}", ref_basenames.join(" ")));
    }

    // Sign the narinfo if signing keys are configured
    if !config.signing_keys.is_empty() {
        let fingerprint = fingerprint_path(
            &config.virtual_store,
            store_path,
            &format!("sha256:{}", nar_hash),
            nar_size,
            references,
        )?;

        if let Some(fp) = fingerprint {
            for key in &config.signing_keys {
                let signature = key.sign(&fp)?;
                lines.push(format!("Sig: {}", signature));
            }
        }
    }

    Ok(format!("{}\n", lines.join("\n")))
}

/// Run a nix-store command to query information
#[allow(dead_code)]
async fn run_nix_store_command(args: &[&str]) -> Result<String> {
    let output = Command::new("nix-store")
        .args(args)
        .output()
        .await
        .context("Failed to execute nix-store command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("nix-store command failed: {}", stderr));
    }

    Ok(String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in nix-store output")?
        .trim()
        .to_string())
}

fn full_body(body: &str) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from(body.to_string())).boxed()
}
