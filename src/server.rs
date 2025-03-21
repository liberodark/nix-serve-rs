use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, UnixListener};
use tokio::signal;
use tracing::{error, info};

use crate::config::Config;
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

        _ => {
            if path.ends_with(".narinfo") && method == Method::GET {
                let hash = path.trim_start_matches('/').trim_end_matches(".narinfo");
                routes::narinfo::get(hash, &config, &store).await
            } else if path.ends_with(".nar") && method == Method::GET {
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
            let mut response = Response::new(full_body("Internal Server Error"));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(response)
        }
    }
}

fn full_body(body: &str) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from(body.to_string())).boxed()
}
