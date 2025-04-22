// fenrir-rust/src/cli.rs
use clap::Parser;
use std::path::PathBuf;
use crate::config::Config; // Import Config for the function signature

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

    // Override IOC file paths
    #[arg(long, value_name = "FILE", env="FENRIR_HASH_IOC_FILE")]
    pub hash_iocs: Option<PathBuf>,

    #[arg(long, value_name = "FILE", env="FENRIR_STRING_IOC_FILE")]
    pub string_iocs: Option<PathBuf>,

    #[arg(long, value_name = "FILE", env="FENRIR_FILENAME_IOC_FILE")]
    pub filename_iocs: Option<PathBuf>,

     #[arg(long, value_name = "FILE", env="FENRIR_C2_IOC_FILE")]
    pub c2_iocs: Option<PathBuf>,

    // Override log file path
    #[arg(long, value_name = "PATTERN", env="FENRIR_LOG_FILE_PATTERN")]
    pub log_file: Option<String>,

    // Toggle checks (use distinct flags for disabling)
    #[arg(long, env="FENRIR_DISABLE_C2_CHECK", action = clap::ArgAction::SetTrue)]
    pub disable_c2_check: bool,

    #[arg(long, env="FENRIR_DISABLE_HASH_CHECK", action = clap::ArgAction::SetTrue)]
    pub disable_hash_check: bool,

    #[arg(long, env="FENRIR_DISABLE_STRING_CHECK", action = clap::ArgAction::SetTrue)]
    pub disable_string_check: bool,

    #[arg(long, env="FENRIR_DISABLE_FILENAME_CHECK", action = clap::ArgAction::SetTrue)]
    pub disable_filename_check: bool,

    #[arg(long, env="FENRIR_ENABLE_TIMEFRAME_CHECK", action = clap::ArgAction::SetTrue)]
    pub enable_timeframe_check: bool,

    // Max file size
    #[arg(long, value_name = "KB", env="FENRIR_MAX_FILE_SIZE_KB")]
    pub max_file_size: Option<u64>,

     // Number of threads
    #[arg(long, short='j', value_name = "N", env="FENRIR_NUM_THREADS")]
    pub threads: Option<usize>,

}

// Corrected: Make function public
pub fn apply_cli_overrides(mut config: Config, args: &CliArgs) -> Config {
    if args.debug { config.debug = true; }
    if let Some(path) = &args.hash_iocs { config.hash_ioc_file = path.clone(); }
    if let Some(path) = &args.string_iocs { config.string_ioc_file = path.clone(); }
    if let Some(path) = &args.filename_iocs { config.filename_ioc_file = path.clone(); }
    if let Some(path) = &args.c2_iocs { config.c2_ioc_file = path.clone(); }
    if let Some(pattern) = &args.log_file { config.log_file = Some(pattern.clone()); }

    if args.disable_c2_check { config.enable_c2_check = false; }
    if args.disable_hash_check { config.enable_hash_check = false; }
    if args.disable_string_check { config.enable_string_check = false; }
    if args.disable_filename_check { config.enable_filename_check = false; }

    if args.enable_timeframe_check { config.enable_timeframe_check = true; }

    if let Some(size) = args.max_file_size { config.max_file_size_kb = size; }
    if let Some(threads) = args.threads { config.num_threads = threads; }

    config
}
