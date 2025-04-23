// fenrir-rust/src/checks/strings.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use crate::logger::{log_debug, log_warn}; // Use macros
use aho_corasick::{AhoCorasick, Match};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf}; // Keep PathBuf import

const STRING_READ_BUFFER_SIZE: usize = 8192; // Read chunks
const MAX_MATCH_DISPLAY_LEN: usize = 100; // Max length of matched line section to display

pub fn check_file_strings(path: &Path, iocs: &IocCollection, config: &Config) -> Result<()> {
    if !config.enable_string_check || iocs.string_ioc_matcher.is_none() {
        return Ok(());
    }
    let matcher = iocs.string_ioc_matcher.as_ref().unwrap(); // Safe due to check above

    log_debug!(config, "String scanning file: {}", path.display());

    let extension = path.extension()
        .and_then(|os| os.to_str())
        .map(|s| s.to_lowercase());

    match extension.as_deref() {
        Some("gz") | Some("z") | Some("zip") if is_in_forced_dir(path, config) => {
            scan_compressed::<GzDecoder<_>>(path, matcher, &iocs.string_ioc_list, "gzip", config)?;
        }
        Some("bz") | Some("bz2") if is_in_forced_dir(path, config) => {
            scan_compressed::<BzDecoder<_>>(path, matcher, &iocs.string_ioc_list, "bzip2", config)?;
        }
        _ => {
            scan_plain(path, matcher, &iocs.string_ioc_list, config)?;
        }
    }

    Ok(())
}

fn is_in_forced_dir(path: &Path, config: &Config) -> bool {
     config.forced_string_match_dirs.iter().any(|forced_dir| {
        path.starts_with(forced_dir) || path == forced_dir
    })
}

// Generic scanner for compressed files
fn scan_compressed<'a, R: Read + 'a>(
    path: &Path,
    matcher: &AhoCorasick,
    ioc_list: &[String],
    file_type: &str, // e.g., "gzip", "bzip2"
    config: &Config,
) -> Result<()> {
    let file = File::open(path).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;
    // Adjust decoder instantiation based on specific crate API if needed
    let decoder = R::new(file);
    let mut reader = BufReader::with_capacity(STRING_READ_BUFFER_SIZE, decoder);

    let mut buffer = Vec::with_capacity(STRING_READ_BUFFER_SIZE);
    let mut matches = Vec::new();

    // Simplify map_err here
    matcher.try_find_iter(&mut reader, &mut buffer, |mat| {
        matches.push(mat);
        true
    }).map_err(FenrirError::Io)?; // Simplified


    if !matches.is_empty() {
        let first_match = matches[0];
        let matched_ioc = &ioc_list[first_match.pattern().as_usize()];
        log_warn!(config, "[!] String match found FILE: {} STRING: {} TYPE: {} MATCH: (binary/compressed match)", path.display(), matched_ioc, file_type);
    }

    Ok(())
}


// Scanner for plain text files
fn scan_plain(
    path: &Path,
    matcher: &AhoCorasick,
    ioc_list: &[String],
    config: &Config,
) -> Result<()> {
    let file = File::open(path).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;
    let reader = BufReader::with_capacity(STRING_READ_BUFFER_SIZE, file);

    for (line_num, line_res) in reader.lines().enumerate() {
        match line_res {
            Ok(line) => {
                 if let Some(mat) = matcher.find(&line) {
                    let matched_ioc = &ioc_list[mat.pattern().as_usize()];
                    let match_context = truncate_match(&line, MAX_MATCH_DISPLAY_LEN);
                    log_warn!(config, "[!] String match found FILE: {} LINE: {} STRING: {} TYPE: plain MATCH: {}",
                        path.display(), line_num + 1, matched_ioc, match_context);
                }
            },
            Err(e) => {
                 log_warn!(config, "Error reading line {} from {}: {}", line_num + 1, path.display(), e);
            }
        }
    }
    Ok(())
}

fn truncate_match(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{} ... (truncated)", &text[..max_len])
    }
}
