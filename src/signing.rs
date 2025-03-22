use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine};
use ed25519_dalek::{Signer, SigningKey as DalekSigningKey};
use std::fs;
use std::path::Path;
use tracing::debug;

use crate::error::{NixServeError, NixServeResult};

// Nix base32 alphabet (omitted: E O U T)
const NIX_BASE32_CHARS: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// A parsed signing key used for signing narinfo files
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// Name of the key (e.g., "cache.example.com-1")
    pub name: String,

    /// The actual Ed25519 signing key
    pub key: DalekSigningKey,
}

/// Parse a Nix signing key from a file
///
/// The key file format is: name:base64_encoded_key
pub fn parse_secret_key(path: &Path) -> Result<SigningKey> {
    let key_content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read signing key from {}", path.display()))?;

    let (name, key_b64) = key_content
        .split_once(':')
        .context("Invalid signing key format: missing colon")?;

    let key_bytes = general_purpose::STANDARD
        .decode(key_b64.trim())
        .context("Failed to decode base64 signing key")?;

    debug!(
        "Read signing key for: {}, length: {}",
        name,
        key_bytes.len()
    );

    // Ed25519 keys can be 32 bytes (secret key only) or 64 bytes (keypair)
    if key_bytes.len() == 32 {
        // Convert to a signing key
        let key = DalekSigningKey::from_bytes(&key_bytes.try_into().unwrap());

        Ok(SigningKey {
            name: name.to_string(),
            key,
        })
    } else if key_bytes.len() == 64 {
        // Split into secret key and public key parts
        let key = DalekSigningKey::from_keypair_bytes(&key_bytes.try_into().unwrap())
            .context("Failed to create Ed25519 signing key from keypair")?;

        Ok(SigningKey {
            name: name.to_string(),
            key,
        })
    } else {
        bail!(
            "Invalid signing key length: expected 32 or 64 bytes, got {}",
            key_bytes.len()
        )
    }
}

/// Sign a string using the provided signing key
pub fn sign_string(key: &SigningKey, message: &str) -> String {
    debug!("Signing message: {}", message);

    // Sign the message
    let signature = key.key.sign(message.as_bytes());

    // Encode the signature in base64
    let sig_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Format as "name:base64_signature"
    let result = format!("{}:{}", key.name, sig_base64);
    debug!("Generated signature: {}", result);

    result
}

/// Convert a byte slice to Nix-compatible base32 encoding
pub fn to_nix_base32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }

    debug!("Converting {} bytes to Nix base32", bytes.len());

    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut bit_count: u8 = 0;

    // Process each byte
    for &b in bytes {
        // Add 8 bits to our buffer
        bits = (bits << 8) | (b as u64);
        bit_count += 8;

        // Extract all complete 5-bit chunks
        while bit_count >= 5 {
            bit_count -= 5;
            let chunk = ((bits >> bit_count) & 0x1F) as usize;
            result.push(char::from(NIX_BASE32_CHARS[chunk]));
        }
    }

    // Handle any remaining bits (less than 5)
    if bit_count > 0 {
        let chunk = ((bits << (5 - bit_count)) & 0x1F) as usize;
        result.push(char::from(NIX_BASE32_CHARS[chunk]));
    }

    result
}

/// Helper function to find the index of a character in the Nix base32 alphabet
fn char_to_index(c: char) -> Result<u8> {
    let c = c.to_ascii_lowercase();
    for (i, &b) in NIX_BASE32_CHARS.iter().enumerate() {
        if b == c as u8 {
            return Ok(i as u8);
        }
    }
    bail!("Invalid Nix base32 character: {}", c)
}

/// Convert a Nix base32 string to bytes
pub fn from_nix_base32(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() || s == "0" {
        return Ok(Vec::new());
    }

    debug!("Converting Nix base32 string to bytes: {}", s);

    // Calculate the output size
    let bit_length = s.len() * 5; // 5 bits per char
    let byte_length = (bit_length + 7) / 8; // Round up to next byte

    let mut result = vec![0u8; byte_length];
    let mut value: u16 = 0; // Buffer for bits
    let mut bits_left: u8 = 0; // Number of bits in buffer

    // Process each input character
    for c in s.chars() {
        // Get the 5-bit value for this character
        let b = char_to_index(c)? as u16;

        // Add these 5 bits to our buffer
        value = (value << 5) | b;
        bits_left += 5;

        // As soon as we have 8 or more bits, we can extract a byte
        while bits_left >= 8 {
            bits_left -= 8;
            let pos = byte_length - ((bits_left as usize + 8 + 7) / 8);
            if pos < byte_length {
                result[pos] = ((value >> bits_left) & 0xFF) as u8;
            }
        }
    }

    debug!("Conversion result: {} bytes", result.len());
    Ok(result)
}

/// Helper function to get the value of a hex character
fn hex_val(c: u8, idx: usize) -> Result<u8> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => bail!("Invalid hex character: {}, index: {}", c as char, idx),
    }
}

/// Convert a hex string to bytes
pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Vec<u8>> {
    let hex = hex.as_ref();

    if hex.len() % 2 != 0 {
        bail!("Invalid hex string: odd length");
    }

    debug!("Converting hex string to bytes: {} chars", hex.len());

    hex.chunks(2)
        .enumerate()
        .map(|(i, pair)| {
            let high = hex_val(pair[0], 2 * i).context("Failed to parse hex character")?;
            let low = hex_val(pair[1], 2 * i + 1).context("Failed to parse hex character")?;
            Ok((high << 4) | low)
        })
        .collect()
}

/// Convert a base16 (hex) hash to Nix base32 format
pub fn convert_base16_to_nix32(hash: &str) -> Result<String> {
    // If the hash is already in Nix base32 format (52 chars), return it as is
    if hash.len() == 52 && hash.chars().all(|c| NIX_BASE32_CHARS.contains(&(c as u8))) {
        return Ok(hash.to_string());
    }

    // Convert from hex to bytes
    let bytes = from_hex(hash).context("Failed to convert hash from hex")?;

    // Convert bytes to Nix base32
    let result = to_nix_base32(&bytes);
    debug!(
        "Converted hash from hex to Nix base32: {} -> {}",
        hash, result
    );

    Ok(result)
}

/// Create a fingerprint for a path in the Nix store
///
/// This is used for signing narinfo files
pub fn fingerprint_path(
    virtual_store: &str,
    store_path: &str,
    nar_hash: &str,
    nar_size: u64,
    references: &[String],
) -> NixServeResult<Option<String>> {
    debug!("Creating fingerprint for path: {}", store_path);

    // Validate store path
    if !store_path.starts_with(virtual_store) {
        return Err(NixServeError::internal(format!(
            "Store path does not start with virtual store: {} vs {}",
            store_path, virtual_store
        )));
    }

    // Validate hash format
    if !nar_hash.starts_with("sha256:") {
        return Err(NixServeError::internal(format!(
            "NAR hash does not start with sha256: {}",
            nar_hash
        )));
    }

    // Verify all references are in the store
    for reference in references {
        if !reference.starts_with(virtual_store) {
            return Err(NixServeError::internal(format!(
                "Reference does not start with virtual store: {} vs {}",
                reference, virtual_store
            )));
        }
    }

    // Generate the fingerprint string
    let refs_str = references.join(",");
    let fingerprint = format!("1;{};{};{};{}", store_path, nar_hash, nar_size, refs_str);

    debug!("Generated fingerprint: {}", fingerprint);
    Ok(Some(fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_nix_base32() {
        // Test vector from Nix
        let bytes = hex::decode("1234567890abcdef").unwrap();
        assert_eq!(to_nix_base32(&bytes), "09i5hhcksnkfd4");

        // Empty
        let empty: Vec<u8> = vec![];
        assert_eq!(to_nix_base32(&empty), "0");
    }

    #[test]
    fn test_from_nix_base32() {
        // Test vector
        let base32 = "09i5hhcksnkfd4";
        let bytes = from_nix_base32(base32).unwrap();
        assert_eq!(hex::encode(bytes), "1234567890abcdef");

        // Error case
        assert!(from_nix_base32("123e").is_err()); // Invalid character 'e'
    }

    #[test]
    fn test_fingerprint_path() {
        let virtual_store = "/nix/store";
        let store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test";
        let nar_hash = "sha256:1234567890abcdef";
        let nar_size = 12345;
        let references = vec![
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dep1".to_string(),
            "/nix/store/cccccccccccccccccccccccccccccccc-dep2".to_string(),
        ];

        let fingerprint =
            fingerprint_path(virtual_store, store_path, nar_hash, nar_size, &references).unwrap();

        assert!(fingerprint.is_some());
        let fp = fingerprint.unwrap();

        // Verify the fingerprint format
        assert!(fp.starts_with("1;"));
        assert!(fp.contains(store_path));
        assert!(fp.contains(nar_hash));
        assert!(fp.contains(&nar_size.to_string()));
        assert!(fp.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-dep1"));
        assert!(fp.contains("cccccccccccccccccccccccccccccccc-dep2"));
    }

    // Test désactivé car il nécessite la dépendance rand
    // #[test]
    // fn test_parse_secret_key() {
    //     // Create a mock key file
    //     let temp_dir = tempfile::tempdir().unwrap();
    //     let key_path = temp_dir.path().join("test.key");
    //
    //     // Generate a random keypair
    //     use rand::rngs::OsRng;
    //     let mut csprng = OsRng;
    //     let keypair = ed25519_dalek::SigningKey::generate(&mut csprng);
    //
    //     // Write in the Nix key format
    //     let key_content = format!(
    //         "test.example.com-1:{}",
    //         general_purpose::STANDARD.encode(keypair.to_bytes())
    //     );
    //     fs::write(&key_path, key_content).unwrap();
    //
    //     // Parse the key
    //     let signing_key = parse_secret_key(&key_path).unwrap();
    //
    //     // Verify the key
    //     assert_eq!(signing_key.name, "test.example.com-1");
    //
    //     // Test signing
    //     let message = "test message";
    //     let signature = sign_string(&signing_key, message);
    //
    //     // Verify that the signature starts with the key name
    //     assert!(signature.starts_with("test.example.com-1:"));
    // }
}
