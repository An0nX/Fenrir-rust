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
use crate::errors::Result; // Removed FenrirError import
use crate::ioc::IocCollection;
use clap::Parser;
// Removed PathBuf import
use std::process::ExitCode;

// Define version matching the original script
const VERSION: &str = "0.9.0-log4shell-rust";

// Import needed macros specifically
use crate::{log_debug, log_error, log_info, log_notice, log_warn};

fn main() -> ExitCode {
    // --- Parse Command Line Arguments ---
    let args = cli::CliArgs::parse();

    // --- Load Configuration ---
    let mut config = match Config::load(args.directory.clone()) {
        Ok(mut cfg) => {
            if args.debug { cfg.debug = true; }
            if let Some(path) = args.hash_iocs { cfg.hash_ioc_file = path; }
            if let Some(path) = args.string_iocs { cfg.string_ioc_file = path; }
            if let Some(path) = args.filename_iocs { cfg.filename_ioc_file = path; }
            if let Some(path) = args.c2_iocs { cfg.c2_ioc_file = path; }
            if let Some(pattern) = args.log_file { cfg.log_file = Some(pattern); }

            // Correctly handle the --disable-c2-check flag (which sets args.enable_c2_check to false)
            // The struct field `enable_c2_check` defaults to true (via Config::load).
            // If the flag is present, args.enable_c2_check becomes false.
            // We want cfg.enable_c2_check to reflect the final state based on the flag.
            cfg.enable_c2_check = args.enable_c2_check; // Directly assign the value derived by clap

            if let Some(size) = args.max_file_size { cfg.max_file_size_kb = size; }
            if let Some(threads) = args.threads { cfg.num_threads = threads; }
            cfg
        }
        Err(e) => {
            // Logger not set up, print directly
            eprintln!("[E] Configuration Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // --- Setup Logging ---
    if let Err(e) = logger::setup_logging(&config) {
        eprintln!("[E] Logging Setup Error: {}", e);
        return ExitCode::FAILURE;
    }

    // --- Print Header ---
    print_header();

    // --- Run the main application logic ---
    // Pass config as a borrow where needed
    match run_scan(&config) {
        Ok(_) => {
            // Pass borrow to log macro
            log_info!(&config, "Finished FENRIR Scan successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Pass borrow to log macro
            log_error!(&config, "FENRIR Scan failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn print_header() {
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
}


// Main application logic separated for clarity and testing
fn run_scan(config: &Config) -> Result<()> { // Takes a borrow

    log_info!(config, "Started FENRIR Scan - version {}", VERSION);
    if let Some(log_path) = config.get_current_log_file_path()? {
         log_info!(config, "Writing logfile to {}", log_path.display());
    } else if config.log_to_file {
        log_warn!(config, "File logging enabled but log path pattern is invalid or missing.");
    }

    system_info::log_system_info(config)?;
    check_requirements(config)?;

    log_info!(config, "[+] Reading IOCs...");
    let iocs = IocCollection::load(config)?;
    log_info!(config, "Loaded {} hash IOCs.", iocs.hashes.len());
    log_info!(config, "Loaded {} string/C2 IOCs for matching.", iocs.string_ioc_list.len() + iocs.c2_iocs.len());
    log_info!(config, "Loaded {} filename IOCs.", iocs.filename_iocs.len());
    log_info!(config, "Loaded {} C2 IOCs (for C2 check).", iocs.c2_iocs.len());

    if config.enable_c2_check {
        if let Err(e) = checks::c2::scan_c2(&iocs, config) {
             log_error!(config, "Error during C2 scan: {}", e);
        }
    } else {
         log_info!(config, "Skipping C2 check as it is disabled.");
    }

    scanner::scan_filesystem(config, &iocs)?;

    Ok(())
}


// Check for essential external commands
fn check_requirements(config: &Config) -> Result<()> { // Takes a borrow
    log_info!(config, "Checking requirements...");
    if config.enable_c2_check {
        match std::process::Command::new("lsof").arg("-v").output() {
            Ok(_) => {
                log_info!(config, "lsof command found.");
            }
            Err(e) => {
                 log_error!(config, "The 'lsof' command is required for C2 checks but was not found or failed to execute: {}", e);
                 log_error!(config, "C2 checks will likely fail or be skipped.");
            }
        }
    }
    Ok(())
}
