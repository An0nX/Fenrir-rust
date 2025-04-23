// fenrir-rust/src/checks/strings.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use crate::logger::{log_debug, log_warn}; // Use macros
use aho_corasick::{AhoCorasick, MatchError}; // Removed Match, Added MatchError
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path; // Removed PathBuf

const STRING_READ_BUFFER_SIZE: usize = 8192;
const MAX_MATCH_DISPLAY_LEN: usize = 100;

pub fn check_file_strings(path: &Path, iocs: &IocCollection, config: &Config) -> Result<()> {
    if !config.enable_string_check || iocs.string_ioc_matcher.is_none() {
        return Ok(());
    }
    let matcher = iocs.string_ioc_matcher.as_ref().unwrap();

    log_debug!(config, "String scanning file: {}", path.display());

    let extension = path.extension()
        .and_then(|os| os.to_str())
        .map(|s| s.to_lowercase());

    // --- Updated Match Logic ---
    let file = File::open(path).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;
    let mut buf_reader: Box<dyn BufRead> = match extension.as_deref() {
        // Handle compressed files only if in specific dirs
        Some("gz") | Some("z") | Some("zip") if is_in_forced_dir(path, config) => {
            log_debug!(config,"Scanning as GZIP");
            Box::new(BufReader::with_capacity(STRING_READ_BUFFER_SIZE, GzDecoder::new(file)))
        }
        Some("bz") | Some("bz2") if is_in_forced_dir(path, config) => {
             log_debug!(config,"Scanning as BZIP2");
             Box::new(BufReader::with_capacity(STRING_READ_BUFFER_SIZE, BzDecoder::new(file)))
        }
        // Default to plain text
        _ => {
            log_debug!(config,"Scanning as plain text");
            Box::new(BufReader::with_capacity(STRING_READ_BUFFER_SIZE, file))
        }
    };

    // Determine file type string for logging based on extension check *before* boxing reader
    let file_type_str = match extension.as_deref() {
         Some("gz") | Some("z") | Some("zip") if is_in_forced_dir(path, config) => "gzip",
         Some("bz") | Some("bz2") if is_in_forced_dir(path, config) => "bzip2",
         _ => "plain",
    };

    // Scan the reader (whether plain or decompressed)
    scan_reader(&mut buf_reader, path, matcher, &iocs.string_ioc_list, file_type_str, config)?;
    // --- End Updated Match Logic ---

    Ok(())
}

fn is_in_forced_dir(path: &Path, config: &Config) -> bool {
     config.forced_string_match_dirs.iter().any(|forced_dir| {
        path.starts_with(forced_dir) || path == forced_dir
    })
}

// Renamed and modified function to accept any BufRead
fn scan_reader(
    reader: &mut dyn BufRead, // Use trait object for flexibility
    path: &Path, // Keep path for logging
    matcher: &AhoCorasick,
    ioc_list: &[String],
    file_type: &str,
    config: &Config,
) -> Result<()> {

    // AhoCorasick stream searching requires byte-oriented reading.
    // If the input might not be UTF-8 (common in compressed/binary),
    // reading line by line can fail. Read chunks instead.
    // Use find_iter directly on the reader.

    let mut matches_found = false; // Track if any match occurred
    for (line_num, result) in reader.lines().enumerate() {
        match result {
            Ok(line) => {
                 // Check if the line contains any of the IOC patterns
                 if let Some(mat) = matcher.find(&line) {
                     let matched_ioc = &ioc_list[mat.pattern().as_usize()];
                     let match_context = truncate_match(&line, MAX_MATCH_DISPLAY_LEN);
                     log_warn!(config, "[!] String match found FILE: {} LINE: {} STRING: {} TYPE: {} MATCH: {}",
                         path.display(), line_num + 1, matched_ioc, file_type, match_context);
                     matches_found = true;
                     // Optimization: Break after first match per file?
                     // break; // Uncomment to report only first match per file
                 }
            }
            Err(e) => {
                 // Attempt to log the error, but continue if it's likely a UTF-8 issue
                 log_warn!(config, "Error reading line {} from {}: {}. Might be non-UTF8 data.", line_num + 1, path.display(), e);
                 // If we hit a read error, stop processing this file.
                 // Consider if specific errors (like UTF8) should allow continuation.
                 // For now, let's be conservative and stop. But this prevents finding matches after bad data.
                 // Option: Continue scan despite line reading errors?
                 // return Err(FenrirError::Io(e)); // Stop on any error
            }
        }
    }

    // Alternative using stream search (handles non-UTF8 better but loses line context):
    // let mut process_match = |mat: &Match| -> bool {
    //     let matched_ioc = &ioc_list[mat.pattern().as_usize()];
    //     log_warn!(config, "[!] String match found FILE: {} STRING: {} TYPE: {} MATCH: (offset {})",
    //         path.display(), matched_ioc, file_type, mat.start());
    //     matches_found = true;
    //     // Return false to stop searching after the first match if desired
    //     // true // Continue searching
    //     false // Stop after first match for performance
    // };
    // matcher.try_stream_find_iter(reader).try_for_each(|result| match result {
    //     Ok(mat) => Ok(process_match(&mat)),
    //     Err(MatchError::Io(e)) => Err(FenrirError::Io(e)),
    //     Err(MatchError::Quit { .. }) => Ok(false), // Indicates search stopped early
    //     // Handle other MatchError variants if necessary
    // })?;

    Ok(())
}


fn truncate_match(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        // Ensure we don't panic slicing potentially non-UTF8 boundaries if text came from bytes
        let mut end = max_len;
        while !text.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{} ... (truncated)", &text[..end])
    }
}
