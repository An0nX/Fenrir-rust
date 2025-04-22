// fenrir-rust/src/main.rs

// Declare modules
mod cli;
mod config;
mod errors;
mod ioc;
mod logger;
mod scanner;
mod checks;
mod system_info;

// Use imports
use crate::config::Config;
use crate::errors::Result; // Removed FenrirError
use crate::ioc::IocCollection;
use clap::Parser;
// Removed: use std::path::PathBuf;
use std::process::ExitCode;

// Define version matching the original script
const VERSION: &str = "0.9.0-log4shell-rust";

// Import macros directly (compiler should find them via mod logger)
use crate::logger::*; // Import all macros

fn main() -> ExitCode {
    // --- Parse Command Line Arguments ---
    let args = cli::CliArgs::parse();

    // --- Load Configuration ---
    let mut config = match Config::load(args.directory.clone()) {
        Ok(cfg) => cfg, // Make mutable here
        Err(e) => {
            eprintln!("[E] Configuration Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // --- Override config from CLI args ---
    // We made config mutable above to allow this
    if args.debug { config.debug = true; }
    if let Some(path) = args.hash_iocs { config.hash_ioc_file = path; }
    if let Some(path) = args.string_iocs { config.string_ioc_file = path; }
    if let Some(path) = args.filename_iocs { config.filename_ioc_file = path; }
    if let Some(path) = args.c2_iocs { config.c2_ioc_file = path; }
    if let Some(pattern) = args.log_file { config.log_file = Some(pattern); }
    // Clap handles boolean flags default true, use count or action for explicit enable/disable
    // Let's assume the clap setup for enable_c2_check uses ArgAction::SetFalse for a --disable-c2-check flag
    if !args.enable_c2_check { config.enable_c2_check = false; }
    if let Some(size) = args.max_file_size { config.max_file_size_kb = size; }
    if let Some(threads) = args.threads { config.num_threads = threads; }


    // --- Setup Logging ---
    // Pass immutable reference now
    if let Err(e) = logger::setup_logging(&config) {
        eprintln!("[E] Logging Setup Error: {}", e);
        return ExitCode::FAILURE;
    }

    // --- Print Header ---
    print_header(&config); // Pass config for logging inside if needed

    // --- Run the main application logic ---
    // Pass immutable reference
    match run_scan(&config) {
        Ok(_) => {
            log_info!(&config, "Finished FENRIR Scan successfully."); // Pass reference
            ExitCode::SUCCESS
        }
        Err(e) => {
            log_error!(&config, "FENRIR Scan failed: {}", e); // Pass reference
            ExitCode::FAILURE
        }
    }
}

// Pass config if header needs logging
fn print_header(config: &Config) {
     // Use eprintln to ensure it shows up even if logging fails early
     eprintln!("##############################################################");
     eprintln!("    ____             _     ");
     eprintln!("   / __/__ ___  ____(_)___ ");
     eprintln!("  / _// -_) _ \\/ __/ / __/ ");
     eprintln!(" /_/  \\__/_//_/_/ /_/_/    ");
     eprintln!(" v{}", VERSION);
     eprintln!(" ");
     eprintln!(" Simple Rust IOC Checker (Rewrite)");
     eprintln!(" Based on Fenrir by Florian Roth");
     eprintln!("##############################################################");
     eprintln!();
     log_info!(config, "Started FENRIR Scan - version {}", VERSION); // Log start message here
}


// Main application logic separated for clarity and testing
fn run_scan(config: &Config) -> Result<()> { // Takes immutable reference

    // Log start message moved to print_header
    if let Some(log_path) = config.get_current_log_file_path()? {
         log_info!(config, "Writing logfile to {}", log_path.display()); // Pass reference
    } else if config.log_to_file {
        log_warn!(config, "File logging enabled but log path pattern is invalid or missing."); // Pass reference
    }

    // --- Log System Information ---
    system_info::log_system_info(config)?; // Pass reference

    // --- Check Requirements (like lsof) ---
    check_requirements(config)?; // Pass reference


    // --- Read IOCs ---
    log_info!(config, "[+] Reading IOCs..."); // Pass reference
    let iocs = IocCollection::load(config)?; // Pass reference
    log_info!(config, "Loaded {} hash IOCs.", iocs.hashes.len()); // Pass reference
    log_info!(config, "Loaded {} string/C2 IOCs for matching.", iocs.string_ioc_list.len() + iocs.c2_iocs.len()); // Pass reference
    log_info!(config, "Loaded {} filename IOCs.", iocs.filename_iocs.len()); // Pass reference
    log_info!(config, "Loaded {} C2 IOCs (for C2 check).", iocs.c2_iocs.len()); // Pass reference


    // --- Perform Scans ---

    // C2 Check (lsof)
    if config.enable_c2_check {
        if let Err(e) = checks::c2::scan_c2(&iocs, config) { // Pass reference
             log_error!(config, "Error during C2 scan: {}", e); // Pass reference
        }
    } else {
         log_info!(config, "Skipping C2 check as it is disabled."); // Pass reference
    }

    // Filesystem Scan
    scanner::scan_filesystem(config, &iocs)?; // Pass reference

    Ok(())
}


// Check for essential external commands (currently only lsof if enabled)
fn check_requirements(config: &Config) -> Result<()> { // Takes immutable reference
    log_info!(config, "Checking requirements..."); // Pass reference
    if config.enable_c2_check {
        match std::process::Command::new("lsof").arg("-v").output() {
            Ok(_) => log_info!(config, "lsof command found."), // Pass reference
            Err(e) => {
                 log_error!(config, "The 'lsof' command is required for C2 checks but was not found or failed to execute: {}", e); // Pass reference
                 log_error!(config, "C2 checks will fail or be skipped."); // Pass reference
            }
        }
    }
    Ok(())
}
