use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey as Ed25519SigningKey};

use crate::crypto::base32::to_nix_base32;
use crate::error::{NixServeError, NixServeResult};

/// A Nix binary cache signing key
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub name: String,
    key: Ed25519SigningKey,
}

impl SigningKey {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read signing key from {}", path.display()))?;

        Self::from_string(&content)
    }

    pub fn from_string(content: &str) -> Result<Self> {
        let (name, key_base64) = content
            .split_once(':')
            .context("Invalid signing key format: missing colon")?;

        let key_bytes = BASE64
            .decode(key_base64.trim())
            .context("Failed to decode base64 signing key")?;

        if key_bytes.len() == 32 {
            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(&key_bytes);

            let key = Ed25519SigningKey::from_bytes(&secret_bytes);

            return Ok(Self {
                name: name.to_string(),
                key,
            });
        } else if key_bytes.len() == 64 {
            let mut keypair_bytes = [0u8; 64];
            keypair_bytes.copy_from_slice(&key_bytes);

            let key = Ed25519SigningKey::from_keypair_bytes(&keypair_bytes)
                .context("Failed to create Ed25519 signing key")?;

            return Ok(Self {
                name: name.to_string(),
                key,
            });
        }

        anyhow::bail!(
            "Invalid signing key length: expected 32 or 64 bytes, got {}",
            key_bytes.len()
        )
    }

    /// Sign a string with this key
    pub fn sign(&self, message: &str) -> NixServeResult<String> {
        // Sign the message
        let signature: Signature = self
            .key
            .try_sign(message.as_bytes())
            .map_err(|e| NixServeError::crypto(format!("Failed to sign message: {}", e)))?;

        // Encode the signature in base64
        let sig_base64 = BASE64.encode(signature.to_bytes());

        // Format as "name:base64_signature"
        Ok(format!("{}:{}", self.name, sig_base64))
    }
}

/// Create a fingerprint for a path in the Nix store
pub fn fingerprint_path(
    virtual_store: &str,
    store_path: &str,
    nar_hash: &str,
    nar_size: u64,
    references: &[String],
) -> NixServeResult<Option<String>> {
    if !store_path.starts_with(virtual_store) {
        return Err(NixServeError::internal(format!(
            "Store path does not start with virtual store: {} vs {}",
            store_path, virtual_store
        )));
    }

    if !nar_hash.starts_with("sha256:") {
        return Err(NixServeError::internal(format!(
            "NAR hash does not start with sha256: {}",
            nar_hash
        )));
    }

    let refs_str = references.join(",");

    let fingerprint = format!("1;{};{};{};{}", store_path, nar_hash, nar_size, refs_str);

    Ok(Some(fingerprint))
}

/// Convert a hex hash to a Nix-compatible base32 representation
pub fn convert_base16_to_nix32(hash: &str) -> NixServeResult<String> {
    let hash_str = hash.strip_prefix("sha256:").unwrap_or(hash);

    let bytes = hex::decode(hash_str)
        .map_err(|e| NixServeError::invalid_hash(format!("Invalid hex hash: {}", e)))?;

    Ok(to_nix_base32(&bytes))
}
