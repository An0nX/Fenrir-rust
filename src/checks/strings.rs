// fenrir-rust/src/checks/strings.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use crate::logger::{log_debug, log_warn}; // Use macros
use aho_corasick::AhoCorasick; // Keep AhoCorasick
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{BufRead, BufReader, Read}; // Added BufRead
use std::path::Path; // Removed PathBuf

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

    // --- Open file once ---
    let file = File::open(path).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;

    // --- Select reader based on extension ---
    match extension.as_deref() {
        Some("gz") | Some("z") if is_in_forced_dir(path, config) => {
            let decoder = GzDecoder::new(file);
            let reader = BufReader::with_capacity(STRING_READ_BUFFER_SIZE, decoder);
            scan_reader(reader, path, "gzip", matcher, &iocs.string_ioc_list, config)?;
        }
        Some("bz") | Some("bz2") if is_in_forced_dir(path, config) => {
            let decoder = BzDecoder::new(file);
            let reader = BufReader::with_capacity(STRING_READ_BUFFER_SIZE, decoder);
            scan_reader(reader, path, "bzip2", matcher, &iocs.string_ioc_list, config)?;
        }
        // Add zip support here if needed using the 'zip' crate
        _ => {
            // Scan plain text file, or any file not specifically decoded if not in forced dir
            let reader = BufReader::with_capacity(STRING_READ_BUFFER_SIZE, file);
            scan_reader(reader, path, "plain", matcher, &iocs.string_ioc_list, config)?;
        }
    }

    Ok(())
}

// Helper to check if path is within a forced string match directory
fn is_in_forced_dir(path: &Path, config: &Config) -> bool {
     config.forced_string_match_dirs.iter().any(|forced_dir| {
        // Check if path starts with forced_dir OR if path *is* the forced_dir (for files like /etc/hosts)
        path.starts_with(forced_dir) || path == forced_dir.as_path()
    })
}

// Scanner for any BufRead reader (plain or decoded)
fn scan_reader<R: BufRead>(
    reader: R, // Take reader directly
    path: &Path,
    file_type: &str, // e.g., "plain", "gzip", "bzip2"
    matcher: &AhoCorasick,
    ioc_list: &[String],
    config: &Config,
) -> Result<()> {
    for (line_num, line_res) in reader.lines().enumerate() {
        match line_res {
            Ok(line) => {
                // Find the first match on the line
                 if let Some(mat) = matcher.find(&line) {
                    let matched_ioc = &ioc_list[mat.pattern().as_usize()];
                    let match_context = truncate_match(&line, MAX_MATCH_DISPLAY_LEN);
                    log_warn!(config, "[!] String match found FILE: {} LINE: {} STRING: {} TYPE: {} MATCH: {}",
                        path.display(), line_num + 1, matched_ioc, file_type, match_context);
                    // Optimization: stop searching this file after first match?
                    // return Ok(()); // Uncomment to report only first match per file
                }
            },
            Err(e) => {
                 // Handle potential non-UTF8 data in compressed files gracefully
                 if e.kind() == std::io::ErrorKind::InvalidData {
                     log_debug!(config, "Skipping non-UTF8 line {} in {}: {}", line_num + 1, path.display(), e);
                      // Try to continue scanning the rest of the file
                     continue;
                 } else {
                     // Log other IO errors more visibly
                     log_warn!(config, "Error reading line {} from {}: {}", line_num + 1, path.display(), e);
                     // Potentially stop scanning this file on significant error?
                     // return Err(FenrirError::Io(e)); // Option: Stop on error
                 }
            }
        }
    }
    Ok(())
}


// Helper to truncate match context
fn truncate_match(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        // Avoid slicing potentially multi-byte UTF-8 characters
        let mut truncated = String::with_capacity(max_len + 10);
        for (i, c) in text.char_indices() {
            if i >= max_len {
                break;
            }
            truncated.push(c);
        }
        format!("{} ... (truncated)", truncated)
    }
}
