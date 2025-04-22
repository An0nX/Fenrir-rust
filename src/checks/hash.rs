// fenrir-rust/src/checks/hash.rs

// УБРАНО: extern crate md5; // Ненужно и не помогло
// УБРАНО: extern crate sha1; // Ненужно
// УБРАНО: extern crate sha2; // Ненужно

use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use crate::logger::{log_debug, log_warn};
use digest::Digest; // <- Импорт трейта для методов .update() / .finalize()
use hex;
use md5::Md5;       // <- Импорт типа Md5
use sha1::Sha1;     // <- Импорт типа Sha1
use sha2::Sha256;   // <- Импорт типа Sha256 из крейта sha2
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

    // --- ИСПРАВЛЕНО: Используем TypeName::new() ---
    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();
    // ---------------------------------------------

    let mut buf = [0u8; HASH_BUFFER_SIZE];
    loop {
        let bytes_read = reader.read(&mut buf).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;
        if bytes_read == 0 { break; }
        let data_slice = &buf[..bytes_read];
        // Используем методы из трейта digest::Digest
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
