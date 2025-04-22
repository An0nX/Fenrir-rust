// fenrir-rust/src/cli.rs
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "fenrir-rust")]
#[command(bin_name = "fenrir-rust")]
pub struct CliArgs {
    /// Start point of the recursive scan
    #[arg(required = true)]
    pub directory: PathBuf,

    /// Enable debug logging
    #[arg(long, env = "FENRIR_DEBUG", action = clap::ArgAction::SetTrue)]
    pub debug: bool,

    // --- Add other important config options as flags if desired ---
    // Example: Override IOC file paths
    #[arg(long, value_name = "FILE", env="FENRIR_HASH_IOC_FILE")]
    pub hash_iocs: Option<PathBuf>,

    #[arg(long, value_name = "FILE", env="FENRIR_STRING_IOC_FILE")]
    pub string_iocs: Option<PathBuf>,

    #[arg(long, value_name = "FILE", env="FENRIR_FILENAME_IOC_FILE")]
    pub filename_iocs: Option<PathBuf>,

     #[arg(long, value_name = "FILE", env="FENRIR_C2_IOC_FILE")]
    pub c2_iocs: Option<PathBuf>,

    // Example: Override log file path
    #[arg(long, value_name = "PATTERN", env="FENRIR_LOG_FILE_PATTERN")]
    pub log_file: Option<String>,

    // Example: Toggle checks
    #[arg(long, env="FENRIR_DISABLE_C2_CHECK", action = clap::ArgAction::SetFalse)] // Note: Action reverses logic for disable flag
    pub enable_c2_check: bool,
     // Add similar flags for other checks if needed

    // Example: Max file size
    #[arg(long, value_name = "KB", env="FENRIR_MAX_FILE_SIZE_KB")]
    pub max_file_size: Option<u64>,

     // Example: Number of threads
    #[arg(long, short='j', value_name = "N", env="FENRIR_NUM_THREADS")]
    pub threads: Option<usize>,

}

// Function to merge CLI args with Config (if CLI overrides are used)
// This is an alternative to pure environment variable config
// For now, we primarily use env vars via Config::load and let clap handle --debug.
// pub fn merge_cli_into_config(mut config: Config, args: &CliArgs) -> Config {
//     if let Some(path) = &args.hash_iocs { config.hash_ioc_file = path.clone(); }
//     // ... merge others ...
//     config
// }
