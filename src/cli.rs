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

    // --- Other config options as flags ---
    #[arg(long, value_name = "FILE", env="FENRIR_HASH_IOC_FILE")]
    pub hash_iocs: Option<PathBuf>,

    #[arg(long, value_name = "FILE", env="FENRIR_STRING_IOC_FILE")]
    pub string_iocs: Option<PathBuf>,

    #[arg(long, value_name = "FILE", env="FENRIR_FILENAME_IOC_FILE")]
    pub filename_iocs: Option<PathBuf>,

     #[arg(long, value_name = "FILE", env="FENRIR_C2_IOC_FILE")]
    pub c2_iocs: Option<PathBuf>,

    #[arg(long, value_name = "PATTERN", env="FENRIR_LOG_FILE_PATTERN")]
    pub log_file: Option<String>,

    // Имя флага изменено для ясности
    /// Disable the C2 check (lsof)
    #[arg(long, env="FENRIR_DISABLE_C2_CHECK", action = clap::ArgAction::SetTrue)]
    pub disable_c2_check: bool, // Это поле будет true, если флаг присутствует

    #[arg(long, value_name = "KB", env="FENRIR_MAX_FILE_SIZE_KB")]
    pub max_file_size: Option<u64>,

    #[arg(long, short='j', value_name = "N", env="FENRIR_NUM_THREADS")]
    pub threads: Option<usize>,
}
