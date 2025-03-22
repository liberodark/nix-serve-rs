use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use http::{Method, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio::signal;
use tracing::{debug, error, info};

mod buildlog;
mod cacheinfo;
mod config;
mod daemon;
mod error;
mod health;
mod nar;
mod narinfo;
mod root;
mod routes;
mod signing;
mod store;
mod version;

use config::{ArgsProvider, Config};
use store::Store;

/// Command line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about = "A high-performance Nix binary cache server")]
struct Args {
    /// Path to configuration file
    #[clap(short, long, env = "NIX_SERVE_CONFIG")]
    config: Option<String>,

    /// Bind address (format: [host]:port or unix:/path/to/socket)
    #[clap(short, long, env = "NIX_SERVE_BIND")]
    bind: Option<String>,

    /// Number of worker threads
    #[clap(short, long, env = "NIX_SERVE_WORKERS")]
    workers: Option<usize>,

    /// Path to signing key
    #[clap(long, env = "NIX_SECRET_KEY_FILE")]
    sign_key: Option<String>,

    /// Whether to compress NARs when serving them
    #[clap(long, env = "NIX_SERVE_COMPRESS_NARS")]
    compress_nars: Option<bool>,

    /// Compression level (1-19 for zstd, 0-9 for xz)
    #[clap(long, env = "NIX_SERVE_COMPRESSION_LEVEL")]
    compression_level: Option<i32>,

    /// Compression format (xz or zstd)
    #[clap(long, env = "NIX_SERVE_COMPRESSION_FORMAT")]
    compression_format: Option<String>,

    /// Quiet mode (suppress info logging)
    #[clap(short, long)]
    quiet: bool,

    /// Verbose mode (enable debug logging)
    #[clap(short, long)]
    verbose: bool,
}

impl ArgsProvider for Args {
    fn bind(&self) -> Option<String> {
        self.bind.clone()
    }

    fn workers(&self) -> Option<usize> {
        self.workers
    }

    fn sign_key(&self) -> Option<String> {
        self.sign_key.clone()
    }

    fn compress_nars(&self) -> Option<bool> {
        self.compress_nars
    }
}

async fn handle_request(
    req: Request<Incoming>,
    config: Arc<Config>,
    store: Arc<Store>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path();
    let headers = req.headers().clone();

    debug!("{} {}", method, path);

    // Collect the body for PUT/POST requests
    let body = if method == Method::PUT || method == Method::POST {
        match req.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(full_body(&format!("Failed to read request body: {}", e)))
                    .unwrap());
            }
        }
    } else {
        Bytes::new()
    };

    let response = match (method.as_str(), path) {
        // Health check
        ("GET", "/health") => health::get().await,

        // Cache info
        ("GET", "/nix-cache-info") => cacheinfo::get(&config).await,

        // Version
        ("GET", "/version") => version::get().await,

        // Root
        ("GET", "/") => root::get(&config).await,

        // NAR HEAD requests
        ("HEAD", _) if path.starts_with("/nar/") => {
            nar::head(path, uri.query(), &config, &store).await
        }

        // NAR PUT requests (uploads)
        ("PUT", _) if path.starts_with("/nar/") => nar::put(path, body, &config, &store).await,

        // NAR GET requests
        ("GET", _) if path.starts_with("/nar/") => {
            nar::get(path, uri.query(), &headers, &config, &store).await
        }

        // NARInfo PUT requests
        ("PUT", _) if path.ends_with(".narinfo") => {
            let hash = path.trim_start_matches('/').trim_end_matches(".narinfo");
            narinfo::put(hash, body, &config, &store).await
        }

        // NARInfo GET requests
        ("GET", _) if path.ends_with(".narinfo") => {
            let hash = path.trim_start_matches('/').trim_end_matches(".narinfo");
            narinfo::get(hash, uri.query(), &config, &store).await
        }

        // Build log requests
        ("GET", _) if path.starts_with("/log/") => {
            let hash = path.trim_start_matches("/log/");
            buildlog::get(hash, &config, &store).await
        }

        // Not found
        _ => {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full_body("Not Found"))
                .unwrap();
            Ok(response)
        }
    };

    match response {
        Ok(resp) => Ok(resp),
        Err(err) => {
            error!("Error handling request: {}", err);
            let response = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full_body(&format!("Internal Server Error: {}", err)))
                .unwrap();
            Ok(response)
        }
    }
}

fn full_body(body: &str) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from(body.to_string())).boxed()
}

async fn run_tcp_server(addr: SocketAddr, config: Arc<Config>, store: Arc<Store>) -> Result<()> {
    info!("Listening on TCP {}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

    // Spawn ctrl-c handler
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

async fn run_unix_server(path: &str, config: Arc<Config>, store: Arc<Store>) -> Result<()> {
    info!("Listening on Unix socket {}", path);

    // Remove existing socket if it exists
    if Path::new(path).exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("Failed to remove existing socket file: {}", path))?;
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("Failed to bind to Unix socket: {}", path))?;

    // Set socket permissions to 777
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o777);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("Failed to set permissions on socket: {}", path))?;
    }

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

    // Spawn ctrl-c handler
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

    // Clean up socket file
    if Path::new(path).exists() {
        if let Err(e) = std::fs::remove_file(path) {
            error!("Failed to remove socket file on shutdown: {}", e);
        }
    }

    info!("Server shutdown complete");
    Ok(())
}

async fn run_server(args: Args) -> Result<()> {
    // Load configuration
    let mut config = if let Some(config_path) = &args.config {
        Config::load(Path::new(config_path))
            .with_context(|| format!("Failed to load config from {}", config_path))?
    } else {
        Config::load_from_env()?
    };

    // Apply command line arguments
    if let Some(bind) = args.bind() {
        config.bind = bind;
    }

    if let Some(workers) = args.workers() {
        config.workers = workers;
    }

    if let Some(sign_key) = args.sign_key() {
        config
            .sign_key_paths
            .push(std::path::PathBuf::from(sign_key));
    }

    if let Some(compress) = args.compress_nars() {
        config.compress_nars = compress;
    }

    if let Some(level) = args.compression_level {
        config.compression_level = level;
    }

    if let Some(format) = args.compression_format {
        config.compression_format = format;
    }

    // Initialize store
    config.store = Store::new(config.virtual_store.clone(), config.real_store.clone());

    // Load signing keys
    for sign_key_path in &config.sign_key_paths {
        let signing_key = signing::parse_secret_key(sign_key_path)
            .with_context(|| format!("Failed to load signing key: {}", sign_key_path.display()))?;

        config.signing_keys.push(signing_key);
    }

    // Create shared config and store
    let config = Arc::new(config);
    let store = Arc::new(config.store.clone());

    info!("Starting nix-serve-rs v{}", env!("CARGO_PKG_VERSION"));
    info!("Binding to {}", config.bind);

    // Determine if we're binding to TCP or Unix socket
    if config.bind.starts_with("unix:") {
        let socket_path = &config.bind[5..];
        run_unix_server(socket_path, Arc::clone(&config), store).await
    } else {
        let addr: SocketAddr = config
            .bind
            .parse()
            .with_context(|| format!("Invalid bind address: {}", config.bind))?;
        run_tcp_server(addr, config, store).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Configure logging
    let log_level = if args.quiet {
        tracing::Level::WARN
    } else if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    // Initialize logging
    tracing_subscriber::fmt().with_max_level(log_level).init();

    // Run the server
    run_server(args).await
}
