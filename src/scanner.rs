// fenrir-rust/src/scanner.rs
use crate::checks::{filename, hash, strings, timeframe}; // Removed c2
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use crate::logger::{log_debug, log_info}; // Use macros
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::{WalkDir}; // Removed DirEntry

pub fn scan_filesystem(config: &Config, iocs: &IocCollection) -> Result<()> {
    log_info!(config, "[+] Scanning path {} ...", config.scan_path.display());

    // --- Determine number of threads ---
    let num_threads = config.num_threads;
    log_info!(config, "Using {} threads for file scanning.", num_threads);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .map_err(|e| FenrirError::Config(format!("Failed to build thread pool: {}", e)))?;


    // --- Prepare filters ---
    // Convert PathBufs in config to Paths for efficient comparison
    let excluded_dirs_paths: Vec<&Path> = config.excluded_dirs.iter().map(|pb| pb.as_path()).collect();
    let forced_string_dirs_paths: Vec<&Path> = config.forced_string_match_dirs.iter().map(|pb| pb.as_path()).collect();


    // --- Walk the directory and collect files to scan ---
    // We collect file paths first to parallelize the checking, not the walking itself easily.
    let files_to_scan: Vec<PathBuf> = WalkDir::new(&config.scan_path)
        .follow_links(false) // Don't follow symbolic links by default
        .into_iter()
        .filter_map(|entry_res| {
            match entry_res {
                Ok(entry) => {
                    // Basic filtering: only files, handle read errors
                    if entry.file_type().is_file() {
                        Some(entry.into_path()) // Keep PathBuf
                    } else {
                        None // Skip directories, symlinks, etc.
                    }
                },
                Err(e) => {
                    // Log errors accessing directory entries but continue
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


    // --- Parallel Scan ---
    files_to_scan.par_iter().for_each(|file_path| {
         // Perform checks for each file - handle errors within the closure
         if let Err(e) = process_file(file_path, config, iocs, &excluded_dirs_paths, &forced_string_dirs_paths) {
            // Log errors encountered during file processing
             log_debug!(config, "Error processing file {}: {}", file_path.display(), e);
        }
    });


    log_info!(config, "Finished filesystem scan.");
    Ok(())
}


// Function to process a single file
fn process_file(
    file_path: &Path,
    config: &Config,
    iocs: &IocCollection,
    excluded_dirs: &[&Path],
    forced_string_dirs: &[&Path],
) -> Result<()> {

    log_debug!(config, "Scanning {}", file_path.display());

    // --- Exclusion Checks ---

    // 1. Excluded Directories
    // Check if the file path starts with any excluded directory path
    if excluded_dirs.iter().any(|ex_dir| file_path.starts_with(ex_dir)) {
        log_debug!(config, "Skipping {} due to exclusion.", file_path.display());
        return Ok(()); // Skip this file entirely
    }

    // --- Get File Metadata (once) ---
    let metadata = match fs::metadata(file_path) {
         Ok(md) => md,
         Err(e) => return Err(FenrirError::FileAccess { path: file_path.to_path_buf(), source: e }),
    };
    let file_size_bytes = metadata.len();
    let file_size_kb = file_size_bytes / 1024;


    // --- Determine which checks to run ---
    let mut do_string_check = config.enable_string_check;
    let mut do_hash_check = config.enable_hash_check;
    let do_date_check = config.enable_timeframe_check; // Controlled by global config
    let do_filename_check = config.enable_filename_check; // Controlled by global config

    let extension_lower = file_path.extension()
        .and_then(|os| os.to_str())
        .map(|s| s.to_lowercase());

    // Check if file type is ELF (requires 'file' command or a Rust alternative)
    // For simplicity and avoiding external 'file' dep, we omit this check for now.
    // Add back if critical. Assume non-ELF unless proven otherwise.
    let is_elf = false; // Placeholder - TODO: Implement if needed

    // 2. Relevant Extension Check (skip string/hash if extension not relevant and not ELF)
    if config.check_only_relevant_extensions && !is_elf {
        match extension_lower.as_deref() {
            Some(ext) if config.relevant_extensions.contains(ext) => {
                // Extension is relevant, keep checks enabled
            }
            _ => {
                // Extension is not relevant or no extension
                log_debug!(config, "Deactivating string/hash checks on {} due to irrelevant extension.", file_path.display());
                do_string_check = false;
                do_hash_check = false;
            }
        }
    }

    // 3. File Size Check (skip string/hash if too large)
    if file_size_kb > config.max_file_size_kb {
        log_debug!(config, "Deactivating string/hash checks on {} due to size ({} KB > {} KB)", file_path.display(), file_size_kb, config.max_file_size_kb);
        do_string_check = false;
        do_hash_check = false;
    }

    // --- Forced Inclusion Checks ---

    // 1. Forced String Check Directory
    // Check if the file path starts with or equals any forced directory/file path
    if !do_string_check && config.enable_string_check { // Only force if currently disabled but globally enabled
         if forced_string_dirs.iter().any(|forced_path| file_path.starts_with(forced_path) || file_path == *forced_path ) {
            log_debug!(config, "Activating string check on {} due to forced directory/path.", file_path.display());
            do_string_check = true;
        }
    }


    // --- Execute Checks ---

    // Filename Check
    if do_filename_check {
         filename::check_filename(file_path, iocs, config); // Does not return error, logs directly
    }

    // String Check
    if do_string_check {
        if let Err(e) = strings::check_file_strings(file_path, iocs, config) {
             log_debug!(config, "Error during string check for {}: {}", file_path.display(), e);
             // Decide whether to continue other checks or propagate error
             // return Err(e); // Uncomment to stop processing this file on string error
        }
    }

    // Hash Check
    if do_hash_check {
         if let Err(e) = hash::check_file_hashes(file_path, iocs, config) {
             log_debug!(config, "Error during hash check for {}: {}", file_path.display(), e);
            // return Err(e); // Uncomment to stop processing this file on hash error
        }
    }

    // Timeframe Check
    if do_date_check {
         if let Err(e) = timeframe::check_timeframe(file_path, config) {
            log_debug!(config, "Error during timeframe check for {}: {}", file_path.display(), e);
            // return Err(e); // Uncomment to stop processing this file on timeframe error
        }
    }

    Ok(())
}
