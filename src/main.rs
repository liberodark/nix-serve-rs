use anyhow::{Context, Result};
use clap::Parser;
use nix_serve_rs::config::{ArgsProvider, Config};
use nix_serve_rs::server::Server;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long, env = "NIX_SERVE_CONFIG")]
    config: Option<String>,

    /// Bind address (format: [host]:port or unix:/path/to/socket)
    #[clap(short, long, env = "NIX_SERVE_BIND")]
    bind: Option<String>,

    #[clap(short, long, env = "NIX_SERVE_WORKERS")]
    workers: Option<usize>,

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

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set default subscriber")?;

    let args = Args::parse();

    let mut config =
        Config::load(args.config.as_deref(), &args).context("Failed to load configuration")?;

    // Apply command-line overrides that aren't part of the ArgsProvider trait
    if let Some(level) = args.compression_level {
        config.compression_level = level;
    }

    if let Some(format) = args.compression_format {
        config.compression_format = format;
    }

    info!("Starting nix-serve-rs v{}", env!("CARGO_PKG_VERSION"));
    info!("Binding to {}", config.bind);

    let server = Server::new(config).context("Failed to create server")?;

    server.run().await.context("Server error")
}
