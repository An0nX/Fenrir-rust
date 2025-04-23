// fenrir-rust/src/scanner.rs
use crate::checks::{filename, hash, strings, timeframe};
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
// Удалены импорты: use crate::{log_debug, log_info};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn scan_filesystem(config: &Config, iocs: &IocCollection) -> Result<()> {
    log_info!(config, "[+] Scanning path {} ...", config.scan_path.display());

    let num_threads = config.num_threads;
    log_info!(config, "Using {} threads for file scanning.", num_threads);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .map_err(|e| FenrirError::Config(format!("Failed to build thread pool: {}", e)))?;

    let excluded_dirs_paths: Vec<&Path> = config.excluded_dirs.iter().map(|pb| pb.as_path()).collect();
    let forced_string_dirs_paths: Vec<&Path> = config.forced_string_match_dirs.iter().map(|pb| pb.as_path()).collect();

    let files_to_scan: Vec<PathBuf> = WalkDir::new(&config.scan_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry_res| {
            match entry_res {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        Some(entry.into_path())
                    } else {
                        None
                    }
                },
                Err(e) => {
                    if let Some(path) = e.path() {
                        log_debug!(config, "Skipping path due to error: {}: {}", path.display(), e);
                    } else {
                        log_debug!(config, "Skipping entry due to error: {}", e);
                    }
                    None
                }
            }
        })
        .collect();

    log_info!(config, "Found {} files to analyze.", files_to_scan.len());

    files_to_scan.par_iter().for_each(|file_path| {
         if let Err(e) = process_file(file_path, config, iocs, &excluded_dirs_paths, &forced_string_dirs_paths) {
             log_debug!(config, "Error processing file {}: {}", file_path.display(), e);
        }
    });

    log_info!(config, "Finished filesystem scan.");
    Ok(())
}

fn process_file(
    file_path: &Path,
    config: &Config,
    iocs: &IocCollection,
    excluded_dirs: &[&Path],
    forced_string_dirs: &[&Path],
) -> Result<()> {

    log_debug!(config, "Scanning {}", file_path.display());

    if excluded_dirs.iter().any(|ex_dir| file_path.starts_with(ex_dir)) {
        log_debug!(config, "Skipping {} due to exclusion.", file_path.display());
        return Ok(());
    }

    let metadata = match fs::metadata(file_path) {
         Ok(md) => md,
         Err(e) => return Err(FenrirError::FileAccess { path: file_path.to_path_buf(), source: e }),
    };
    let file_size_kb = metadata.len() / 1024;

    let mut do_string_check = config.enable_string_check;
    let mut do_hash_check = config.enable_hash_check;
    let do_date_check = config.enable_timeframe_check;
    let do_filename_check = config.enable_filename_check;

    let extension_lower = file_path.extension()
        .and_then(|os| os.to_str())
        .map(|s| s.to_lowercase());

    let is_elf = false;

    if config.check_only_relevant_extensions && !is_elf {
        match extension_lower.as_deref() {
            Some(ext) if config.relevant_extensions.contains(ext) => {}
            _ => {
                log_debug!(config, "Deactivating string/hash checks on {} due to irrelevant extension.", file_path.display());
                do_string_check = false;
                do_hash_check = false;
            }
        }
    }

    if file_size_kb > config.max_file_size_kb {
        log_debug!(config, "Deactivating string/hash checks on {} due to size ({} KB > {} KB)", file_path.display(), file_size_kb, config.max_file_size_kb);
        do_string_check = false;
        do_hash_check = false;
    }

    if !do_string_check && config.enable_string_check && forced_string_dirs.iter().any(|forced_path| file_path.starts_with(forced_path) || file_path == *forced_path ) {
        log_debug!(config, "Activating string check on {} due to forced directory/path.", file_path.display());
        do_string_check = true;
    }

    if do_filename_check {
         filename::check_filename(file_path, iocs, config);
    }

    if do_string_check {
        if let Err(e) = strings::check_file_strings(file_path, iocs, config) {
             log_debug!(config, "Error during string check for {}: {}", file_path.display(), e);
        }
    }

    if do_hash_check {
         if let Err(e) = hash::check_file_hashes(file_path, iocs, config) {
             log_debug!(config, "Error during hash check for {}: {}", file_path.display(), e);
        }
    }

    if do_date_check {
         if let Err(e) = timeframe::check_timeframe(file_path, config) {
            log_debug!(config, "Error during timeframe check for {}: {}", file_path.display(), e);
        }
    }

    Ok(())
}
