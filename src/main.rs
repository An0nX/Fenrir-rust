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
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

// Define version matching the original script
const VERSION: &str = "0.9.0-log4shell-rust";

// Re-export log macros for use in main
use crate::logger::{log_debug, log_error, log_info, log_warn, log_notice};

fn main() -> ExitCode {
    // --- Parse Command Line Arguments ---
    // Using clap which automatically handles --help, --version etc.
    let args = cli::CliArgs::parse();

    // --- Load Configuration ---
    // Primarily uses environment variables, but gets scan path and debug from CLI args
    let config = match Config::load(args.directory.clone()) {
        Ok(mut cfg) => {
            // Override debug flag from CLI if set
            if args.debug {
                cfg.debug = true;
            }
             // Override other CLI args if provided (demonstration)
             if let Some(path) = args.hash_iocs { cfg.hash_ioc_file = path; }
             if let Some(path) = args.string_iocs { cfg.string_ioc_file = path; }
             if let Some(path) = args.filename_iocs { cfg.filename_ioc_file = path; }
             if let Some(path) = args.c2_iocs { cfg.c2_ioc_file = path; }
             if let Some(pattern) = args.log_file { cfg.log_file = Some(pattern); }
             if !args.enable_c2_check { cfg.enable_c2_check = false; } // If --disable-c2-check flag was used
             if let Some(size) = args.max_file_size { cfg.max_file_size_kb = size; }
             if let Some(threads) = args.threads { cfg.num_threads = threads; }
            cfg
        }
        Err(e) => {
            // Use eprintln directly as logger isn't set up yet
            eprintln!("[E] Configuration Error: {}", e);
            return ExitCode::FAILURE;
        }
    };


    // --- Setup Logging ---
    if let Err(e) = logger::setup_logging(&config) {
        eprintln!("[E] Logging Setup Error: {}", e);
        // Might still be able to log basic info to stderr if console logging failed partially
        return ExitCode::FAILURE;
    }

    // --- Print Header ---
    print_header();

    // --- Run the main application logic ---
    match run_scan(&config) {
        Ok(_) => {
            log_info!(config, "Finished FENRIR Scan successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            log_error!(config, "FENRIR Scan failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn print_header() {
    // Use tracing::info! which will be captured by the configured logger
    // Or print directly to stderr if preferred before logging is fully active
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
     eprintln!(); // Add a newline
}


// Main application logic separated for clarity and testing
fn run_scan(config: &Config) -> Result<()> {

    log_info!(config, "Started FENRIR Scan - version {}", VERSION);
    if let Some(log_path) = config.get_current_log_file_path()? {
         log_info!(config, "Writing logfile to {}", log_path.display());
    } else if config.log_to_file {
        log_warn!(config, "File logging enabled but log path pattern is invalid or missing.");
    }

    // --- Log System Information ---
    system_info::log_system_info(config)?; // Log system info early

    // --- Check Requirements (like lsof) ---
    // Note: lsof check is now done inside scan_c2 if enabled
    check_requirements(config)?;


    // --- Read IOCs ---
    log_info!(config, "[+] Reading IOCs...");
    let iocs = IocCollection::load(config)?;
    log_info!(config, "Loaded {} hash IOCs.", iocs.hashes.len());
    log_info!(config, "Loaded {} string/C2 IOCs for matching.", iocs.string_ioc_list.len() + iocs.c2_iocs.len());
    log_info!(config, "Loaded {} filename IOCs.", iocs.filename_iocs.len());
    log_info!(config, "Loaded {} C2 IOCs (for C2 check).", iocs.c2_iocs.len());


    // --- Perform Scans ---

    // C2 Check (lsof)
    if config.enable_c2_check {
        if let Err(e) = checks::c2::scan_c2(&iocs, config) {
             log_error!(config, "Error during C2 scan: {}", e);
             // Decide if this is fatal. Let's continue filesystem scan for now.
        }
    } else {
         log_info!(config, "Skipping C2 check as it is disabled.");
    }

    // Filesystem Scan
    scanner::scan_filesystem(config, &iocs)?;

    Ok(())
}


// Check for essential external commands (currently only lsof if enabled)
fn check_requirements(config: &Config) -> Result<()> {
    log_info!(config, "Checking requirements...");
    if config.enable_c2_check {
        match std::process::Command::new("lsof").arg("-v").output() {
            Ok(_) => log_info!(config, "lsof command found."),
            Err(e) => {
                 log_error!(config, "The 'lsof' command is required for C2 checks but was not found or failed to execute: {}", e);
                 log_error!(config, "C2 checks will fail or be skipped.");
                 // Return error to potentially halt execution if C2 check is critical?
                 // return Err(FenrirError::UtilityNotFound { name: "lsof".to_string(), source: e });
            }
        }
    }
    // Add checks for other external deps if introduced (e.g., 'file' command)
    Ok(())
}
