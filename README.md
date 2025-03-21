# nix-serve-rs

A high-performance Nix binary cache server implemented in pure Rust.

## Description

nix-serve-rs is a reimplementation of the standard Nix binary cache server (nix-serve) in Rust. This project aims to provide better performance, enhanced security, and improved reliability while maintaining full compatibility with existing Nix clients.

## Advantages

- **Performance**: Uses Tokio and Hyper for asynchronous request handling, offering better performance under heavy load
- **Security**: Strong typing and robust error handling through Rust's type system
- **Reliability**: Less susceptible to memory errors and resource leaks
- **Maintainability**: Well-structured and modern code
- **Extensibility**: Modular architecture makes it easy to add new features

## Prerequisites

- Rust (2021 edition or later)
- Nix installed on the system
- Access to a valid Nix store

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/liberodark/nix-serve-rs.git
cd nix-serve-rs

# Build in release mode
cargo build --release

# The executable is at target/release/nix-serve-rs
```

### Via Nix

```bash
nix-env -i -f https://github.com/liberodark/nix-serve-rs/archive/main.tar.gz
```

or add to your NixOS configuration:

```nix
{
  services.nix-serve-rs = {
    enable = true;
    port = 5000;
    secretKeyFile = "/path/to/your/secret/key";
  };
}
```

## Configuration

nix-serve-rs can be configured via a TOML file or command-line arguments. Command-line arguments take precedence over the configuration file.

### Configuration File (example)

```toml
# nix-serve-rs configuration
bind = "[::]:5000"
workers = 4
max_connections = 1024
priority = 30
virtual_store = "/nix/store"
real_store = "/mnt/nix/store"  # Optional, for stores mounted elsewhere
sign_key_paths = ["/etc/nix/signing-key.sec"]
```

### Command-Line Options

```
USAGE:
    nix-serve-rs [OPTIONS]

OPTIONS:
    -c, --config <CONFIG>           Path to configuration file
    -b, --bind <BIND>               Bind address ([host]:port or unix:/path/to/socket)
    -w, --workers <WORKERS>         Number of worker threads
        --sign-key <SIGN_KEY>       Path to signing key file
    -h, --help                      Print help information
    -V, --version                   Print version information
```

## Usage

### Starting the Server

```bash
# Start with default configuration (listens on [::]:5000)
nix-serve-rs

# Use a configuration file
nix-serve-rs --config /etc/nix-serve-rs.toml

# Listen on a specific port
nix-serve-rs --bind 127.0.0.1:8080

# Use a Unix socket
nix-serve-rs --bind unix:/run/nix-serve-rs.sock
```

### Using the Binary Cache

To use this server as a binary cache in your Nix configuration:

```bash
# Substitute with your URL
echo "trusted-substituters = http://your-server:5000" >> /etc/nix/nix.conf
echo "trusted-public-keys = your-public-key:base64..." >> /etc/nix/nix.conf
```

Or in NixOS configuration:

```nix
{
  nix = {
    binaryCaches = [ "http://your-server:5000" ];
    binaryCachePublicKeys = [ "your-public-key:base64..." ];
  };
}
```

## HTTP API

nix-serve-rs exposes the following endpoints:

- `GET /` - Home page with cache information
- `GET /nix-cache-info` - Binary cache information
- `GET /nar/{hash}.nar` - NAR file download
- `GET /{hash}.narinfo` - Nix store path metadata
- `GET /log/{hash}` - Build log for a derivation
- `GET /health` - Health check endpoint
- `GET /version` - Server version
