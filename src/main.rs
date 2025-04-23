// fenrir-rust/src/main.rs

// Declare modules
mod cli;
mod config;
mod errors;
mod ioc;
mod logger; // Модуль логгера объявляется здесь
mod scanner;
mod checks;
mod system_info;

// Use imports (НЕ импортируем макросы явно)
use crate::config::Config;
use crate::errors::Result; // FenrirError не используется напрямую в main
use crate::ioc::IocCollection;
use clap::Parser;
use std::process::ExitCode;

// Define version matching the original script
const VERSION: &str = "0.9.0-log4shell-rust";

// Макросы log_info!, log_error! и т.д. доступны глобально из модуля logger

fn main() -> ExitCode {
    // --- Parse Command Line Arguments ---
    let args = cli::CliArgs::parse();

    // --- Load Configuration ---
    // Сначала создаем config, потом применяем переопределения из CLI
    let mut config = match Config::load(args.directory.clone()) {
         Ok(cfg) => cfg,
         Err(e) => {
             eprintln!("[E] Configuration Error: {}", e); // Логгер еще не настроен
             return ExitCode::FAILURE;
         }
    };

    // Применяем переопределения из CLI к загруженному config
    if args.debug { config.debug = true; }
    if let Some(path) = args.hash_iocs { config.hash_ioc_file = path; }
    if let Some(path) = args.string_iocs { config.string_ioc_file = path; }
    if let Some(path) = args.filename_iocs { config.filename_ioc_file = path; }
    if let Some(path) = args.c2_iocs { config.c2_ioc_file = path; }
    if let Some(pattern) = args.log_file { config.log_file = Some(pattern); }

    // Используем правильное имя поля из clap: `disable_c2_check`
    // Если флаг --disable-c2-check указан, args.disable_c2_check будет true.
    // Устанавливаем поле конфига `enable_c2_check` в false в этом случае.
    if args.disable_c2_check {
        config.enable_c2_check = false;
    }
    // Если флаг не указан, args.disable_c2_check будет false, и config.enable_c2_check останется true (значение по умолчанию).

    if let Some(size) = args.max_file_size { config.max_file_size_kb = size; }
    if let Some(threads) = args.threads { config.num_threads = threads; }


    // --- Setup Logging ---
    // Передаем config по ссылке
    if let Err(e) = logger::setup_logging(&config) {
        eprintln!("[E] Logging Setup Error: {}", e);
        return ExitCode::FAILURE;
    }

    // --- Print Header ---
    print_header();

    // --- Run the main application logic ---
    // Передаем config по ссылке
    match run_scan(&config) {
        Ok(_) => {
            // Вызываем макросы напрямую, передавая ссылку
            log_info!(&config, "Finished FENRIR Scan successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Вызываем макросы напрямую, передавая ссылку
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
fn run_scan(config: &Config) -> Result<()> { // Принимает ссылку

    // Вызываем макросы напрямую
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
fn check_requirements(config: &Config) -> Result<()> { // Принимает ссылку
    // Вызываем макросы напрямую
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
