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
use std::path::{Path, PathBuf};

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
        // Check compressed files only if in specific dirs (like /var/log/)
        Some("gz") | Some("z") | Some("zip") if is_in_forced_dir(path, config) => {
            scan_compressed::<GzDecoder<_>>(path, matcher, &iocs.string_ioc_list, "gzip", config)?;
        }
        Some("bz") | Some("bz2") if is_in_forced_dir(path, config) => {
            scan_compressed::<BzDecoder<_>>(path, matcher, &iocs.string_ioc_list, "bzip2", config)?;
        }
        // Add zip support here if needed using the 'zip' crate
        _ => {
            // Scan plain text file
            scan_plain(path, matcher, &iocs.string_ioc_list, config)?;
        }
    }

    Ok(())
}

// Helper to check if path is within a forced string match directory
fn is_in_forced_dir(path: &Path, config: &Config) -> bool {
     config.forced_string_match_dirs.iter().any(|forced_dir| {
        // Check if path starts with forced_dir OR if path *is* the forced_dir (for files like /etc/hosts)
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
    let decoder = R::new(file); // Wrap file stream in decoder (assuming constructor is `new`)
                                // Adjust constructor based on actual crate API (e.g., GzDecoder::new)
    let reader = BufReader::with_capacity(STRING_READ_BUFFER_SIZE, decoder);

    // Need to read line by line if possible, otherwise match across buffer boundaries
    // AhoCorasick can search &[u8], so reading chunks is fine.
    let mut buffer = Vec::with_capacity(STRING_READ_BUFFER_SIZE);
    let mut file_content_reader = reader; // Avoid moving reader into find_iter

    // Read the entire decompressed stream (potentially large!) or process in chunks
    // For simplicity and safety against massive logs, process line by line if possible
    // But BufReader<Decoder> might not implement lines(). Let's read chunks.
    // NOTE: This reads the *entire* decompressed file into memory for matching if not careful.
    // A streaming approach with AhoCorasick is better for large files.
    // Let's use the chunked approach with find_iter_read

    let mut matches = Vec::new();
    matcher.try_find_iter(&mut file_content_reader, &mut buffer, |mat| {
        matches.push(mat); // Collect matches
        true // Continue searching
    }).map_err(|e| FenrirError::Io(e))?; // Propagate IO errors from reading

    if !matches.is_empty() {
        // To report the line, we'd ideally need line context which is lost here.
        // We can report the matched IOC string.
        // For more context, we'd need a different approach (line-by-line reading if supported).
        // Report first match found for simplicity, similar to grep's behavior on first match per line.
        let first_match = matches[0]; // Get the first match details
        let matched_ioc = &ioc_list[first_match.pattern().as_usize()]; // Get the original IOC string
        // Cannot easily get the surrounding text from the chunked read here without more complex buffering.
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
                // Find the first match on the line
                 if let Some(mat) = matcher.find(&line) {
                    let matched_ioc = &ioc_list[mat.pattern().as_usize()];
                    let match_context = truncate_match(&line, MAX_MATCH_DISPLAY_LEN);
                    log_warn!(config, "[!] String match found FILE: {} LINE: {} STRING: {} TYPE: plain MATCH: {}",
                        path.display(), line_num + 1, matched_ioc, match_context);
                    // Optimization: stop searching this file after first match?
                    // return Ok(()); // Uncomment to report only first match per file
                }
            },
            Err(e) => {
                // Log error reading line, but continue scan if possible
                 log_warn!(config, "Error reading line {} from {}: {}", line_num + 1, path.display(), e);
                 // Potentially stop scanning this file on error?
                 // return Err(FenrirError::Io(e));
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
        format!("{} ... (truncated)", &text[..max_len])
    }
}
