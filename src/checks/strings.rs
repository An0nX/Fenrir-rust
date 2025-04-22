// fenrir-rust/src/checks/strings.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use crate::logger::{log_debug, log_warn};
use aho_corasick::AhoCorasick;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{BufRead, BufReader}; // Removed unused Read
use std::path::Path;

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

    let file = File::open(path).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;

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
        _ => {
            let reader = BufReader::with_capacity(STRING_READ_BUFFER_SIZE, file);
            scan_reader(reader, path, "plain", matcher, &iocs.string_ioc_list, config)?;
        }
    }

    Ok(())
}

fn is_in_forced_dir(path: &Path, config: &Config) -> bool {
     config.forced_string_match_dirs.iter().any(|forced_dir| {
        path.starts_with(forced_dir) || path == forced_dir.as_path()
    })
}

fn scan_reader<R: BufRead>(
    reader: R,
    path: &Path,
    file_type: &str,
    matcher: &AhoCorasick,
    ioc_list: &[String],
    config: &Config,
) -> Result<()> {
    for (line_num, line_res) in reader.lines().enumerate() {
        match line_res {
            Ok(line) => {
                 if let Some(mat) = matcher.find(&line) {
                    let matched_ioc = &ioc_list[mat.pattern().as_usize()];
                    let match_context = truncate_match(&line, MAX_MATCH_DISPLAY_LEN);
                    log_warn!(config, "[!] String match found FILE: {} LINE: {} STRING: {} TYPE: {} MATCH: {}",
                        path.display(), line_num + 1, matched_ioc, file_type, match_context);
                    // return Ok(()); // Uncomment to report only first match per file
                }
            },
            Err(e) => {
                 if e.kind() == std::io::ErrorKind::InvalidData {
                     log_debug!(config, "Skipping non-UTF8 line {} in {}: {}", line_num + 1, path.display(), e);
                     continue;
                 } else {
                     log_warn!(config, "Error reading line {} from {}: {}", line_num + 1, path.display(), e);
                     // return Err(FenrirError::Io(e)); // Option: Stop on error
                 }
            }
        }
    }
    Ok(())
}

fn truncate_match(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
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
