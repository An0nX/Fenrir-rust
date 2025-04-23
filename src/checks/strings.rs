// fenrir-rust/src/checks/strings.rs
use crate::config::Config;
use crate::errors::{FenrirError, Result}; // Исправлен порядок
use crate::ioc::IocCollection;
// Возвращаем импорты макросов
use crate::{log_debug, log_warn};
use aho_corasick::AhoCorasick;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const STRING_READ_BUFFER_SIZE: usize = 8192;
const MAX_MATCH_DISPLAY_LEN: usize = 100;

pub fn check_file_strings(path: &Path, iocs: &IocCollection, config: &Config) -> Result<()> {
    if !config.enable_string_check || iocs.string_ioc_matcher.is_none() {
        return Ok(());
    }
    let matcher = iocs.string_ioc_matcher.as_ref().unwrap();

    log_debug!(config, "String scanning file: {}", path.display());

    // Отформатировано
    let extension = path
        .extension()
        .and_then(|os| os.to_str())
        .map(|s| s.to_lowercase());

    // Отформатировано
    let file = File::open(path).map_err(|e| FenrirError::FileAccess {
        path: path.to_path_buf(),
        source: e,
    })?;
    let file_type_str: &str;
    let mut buf_reader: Box<dyn BufRead> = match extension.as_deref() {
        Some("gz") | Some("z") | Some("zip") if is_in_forced_dir(path, config) => {
            // Отформатировано
            log_debug!(config, "Scanning as GZIP");
            file_type_str = "gzip";
            // Отформатировано
            Box::new(BufReader::with_capacity(
                STRING_READ_BUFFER_SIZE,
                GzDecoder::new(file),
            ))
        }
        Some("bz") | Some("bz2") if is_in_forced_dir(path, config) => {
            // Отформатировано
            log_debug!(config, "Scanning as BZIP2");
            file_type_str = "bzip2";
            // Отформатировано
            Box::new(BufReader::with_capacity(
                STRING_READ_BUFFER_SIZE,
                BzDecoder::new(file),
            ))
        }
        _ => {
            // Отформатировано
            log_debug!(config, "Scanning as plain text");
            file_type_str = "plain";
            Box::new(BufReader::with_capacity(STRING_READ_BUFFER_SIZE, file))
        }
    };

    // Отформатировано
    scan_reader(
        &mut buf_reader,
        path,
        matcher,
        &iocs.string_ioc_list,
        file_type_str,
        config,
    )?;

    Ok(())
}

// Отформатировано
fn is_in_forced_dir(path: &Path, config: &Config) -> bool {
    config
        .forced_string_match_dirs
        .iter()
        .any(|forced_dir| path.starts_with(forced_dir) || path == forced_dir)
}

fn scan_reader(
    reader: &mut dyn BufRead,
    path: &Path,
    matcher: &AhoCorasick,
    ioc_list: &[String],
    file_type: &str,
    config: &Config,
) -> Result<()> {
    for (line_num, result) in reader.lines().enumerate() {
        match result {
            Ok(line) => {
                if let Some(mat) = matcher.find(&line) {
                    let matched_ioc = &ioc_list[mat.pattern().as_usize()];
                    let match_context = truncate_match(&line, MAX_MATCH_DISPLAY_LEN);
                    log_warn!(
                        config,
                        "[!] String match found FILE: {} LINE: {} STRING: {} TYPE: {} MATCH: {}",
                        path.display(),
                        line_num + 1,
                        matched_ioc,
                        file_type,
                        match_context
                    );
                }
            }
            Err(e) => {
                log_warn!(
                    config,
                    "Error reading line {} from {}: {}. Might be non-UTF8 data.",
                    line_num + 1,
                    path.display(),
                    e
                );
            }
        }
    }
    Ok(())
}

fn truncate_match(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        let mut end = max_len;
        while !text.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{} ... (truncated)", &text[..end])
    }
}
