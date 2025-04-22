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
use crate::errors::Result;
use crate::ioc::IocCollection;
use clap::Parser;
use std::process::ExitCode;

// Import macros directly from logger module
use crate::logger::*;

// Define version matching the original script
const VERSION: &str = "0.9.0-log4shell-rust";


fn main() -> ExitCode {
    // --- Parse Command Line Arguments ---
    let args = cli::CliArgs::parse();

    // --- Load Configuration (primarily from Env) ---
    let config_from_env = match Config::load(args.directory.clone()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[E] Configuration Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // --- Apply CLI Overrides ---
    let config = cli::apply_cli_overrides(config_from_env, &args);


    // --- Setup Logging ---
    if let Err(e) = logger::setup_logging(&config) {
        eprintln!("[E] Logging Setup Error: {}", e);
        // Attempt to log error if possible, otherwise rely on eprintln
        log_error!(&config, "Logging setup failed: {}", e);
        return ExitCode::FAILURE;
    }

    // --- Print Header ---
    print_header(&config);

    // --- Run the main application logic ---
    match run_scan(&config) {
        Ok(_) => {
            log_info!(&config, "Finished FENRIR Scan successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            log_error!(&config, "FENRIR Scan failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn print_header(config: &Config) {
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
     log_info!(config, "Started FENRIR Scan - version {}", VERSION);
}


// Main application logic separated
fn run_scan(config: &Config) -> Result<()> {

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

    // C2 Check (lsof)
    if config.enable_c2_check {
        if let Err(e) = checks::c2::scan_c2(&iocs, config) {
             log_error!(config, "Error during C2 scan: {}", e);
             // Continue filesystem scan despite C2 error
        }
    } else {
         log_info!(config, "Skipping C2 check as it is disabled.");
    }

    // Filesystem Scan
    scanner::scan_filesystem(config, &iocs)?;

    Ok(())
}


// Check for essential external commands
fn check_requirements(config: &Config) -> Result<()> {
    log_info!(config, "Checking requirements...");
    if config.enable_c2_check {
        match std::process::Command::new("lsof").arg("-v").output() {
            Ok(_) => log_info!(config, "lsof command found."),
            Err(e) => {
                 log_error!(config, "The 'lsof' command is required for C2 checks but was not found or failed to execute: {}", e);
                 log_error!(config, "C2 checks will fail or be skipped.");
                 // Do not return error here, allow scan to continue without C2 checks
                 // return Err(FenrirError::UtilityNotFound { name: "lsof".to_string(), source: e });
            }
        }
    }
    Ok(())
}
