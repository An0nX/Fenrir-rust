// fenrir-rust/src/checks/hash.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use crate::logger::{log_debug, log_warn};
use digest::Digest; // Generic trait
use hex;
extern crate md5; // Specific type for Md5::new()
extern crate sha1; // Specific type for Sha1::new()
extern crate sha2; // Specific type for Sha256::new()
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const HASH_BUFFER_SIZE: usize = 8192;

pub fn check_file_hashes(path: &Path, iocs: &IocCollection, config: &Config) -> Result<()> {
    if !config.enable_hash_check || iocs.hashes.is_empty() {
        return Ok(());
    }

    log_debug!(config, "Hashing file: {}", path.display());

    let file = File::open(path).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER_SIZE, file);

    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    let mut buf = [0u8; HASH_BUFFER_SIZE];
    loop {
        let bytes_read = reader.read(&mut buf).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;
        if bytes_read == 0 { break; }
        let data_slice = &buf[..bytes_read];
        md5_hasher.update(data_slice);
        sha1_hasher.update(data_slice);
        sha256_hasher.update(data_slice);
    }

    let md5_digest = md5_hasher.finalize();
    let sha1_digest = sha1_hasher.finalize();
    let sha256_digest = sha256_hasher.finalize();

    let md5_hex = hex::encode(md5_digest);
    let sha1_hex = hex::encode(sha1_digest);
    let sha256_hex = hex::encode(sha256_digest);

    log_debug!(config, "Checking hashes for {}: MD5={}, SHA1={}, SHA256={}", path.display(), md5_hex, sha1_hex, sha256_hex);

    if let Some(description) = iocs.hashes.get(&md5_hex) {
        log_warn!(config, "[!] Hash match found FILE: {} HASH: {} (MD5) DESCRIPTION: {}", path.display(), md5_hex, description);
    }
    if let Some(description) = iocs.hashes.get(&sha1_hex) {
         log_warn!(config, "[!] Hash match found FILE: {} HASH: {} (SHA1) DESCRIPTION: {}", path.display(), sha1_hex, description);
    }
    if let Some(description) = iocs.hashes.get(&sha256_hex) {
        log_warn!(config, "[!] Hash match found FILE: {} HASH: {} (SHA256) DESCRIPTION: {}", path.display(), sha256_hex, description);
    }

    Ok(())
}
