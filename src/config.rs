// fenrir-rust/src/config.rs
use crate::errors::{FenrirError, Result};
use crate::system_info::get_hostname; // Import from the correct module
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;

const DEFAULT_MAX_FILE_SIZE_KB: u64 = 8000;
const DEFAULT_HASH_IOC_FILE: &str = "./hash-iocs.txt";
const DEFAULT_STRING_IOC_FILE: &str = "./string-iocs.txt";
const DEFAULT_FILENAME_IOC_FILE: &str = "./filename-iocs.txt";
const DEFAULT_C2_IOC_FILE: &str = "./c2-iocs.txt";
const DEFAULT_LOG_FILE_PATTERN: &str = "./FENRIR_{HOSTNAME}_{DATE}.log";
const DEFAULT_SYSLOG_FACILITY: &str = "local4";

lazy_static! {
    static ref DEFAULT_RELEVANT_EXTENSIONS: HashSet<String> = {
        let exts = ["jsp", "jspx", "txt", "tmp", "pl", "war", "sh", "log", "jar"];
        exts.iter().map(|s| s.to_string()).collect()
    };
    static ref DEFAULT_EXCLUDED_DIRS: HashSet<PathBuf> = {
        let dirs = ["/proc/", "/initctl/", "/dev/", "/media/"];
        dirs.iter().map(PathBuf::from).collect()
    };
    static ref DEFAULT_FORCED_STRING_MATCH_DIRS: HashSet<PathBuf> = {
        let dirs = ["/var/log/", "/etc/hosts", "/etc/crontab"]; // Note: files are included here too
        dirs.iter().map(PathBuf::from).collect()
    };
     static ref DEFAULT_EXCLUDE_LOG_STRINGS: HashSet<String> = {
        let strs = ["iocs.txt", "fenrir"]; // Add fenrir-rust?
        strs.iter().map(|s| s.to_string()).collect()
    };
}

#[derive(Debug, Clone)]
pub struct Config {
    pub scan_path: PathBuf,
    pub hash_ioc_file: PathBuf,
    pub string_ioc_file: PathBuf,
    pub filename_ioc_file: PathBuf,
    pub c2_ioc_file: PathBuf,
    pub log_file: Option<String>,
    pub log_to_file: bool,
    pub log_to_syslog: bool,
    pub log_to_cmdline: bool,
    #[cfg_attr(not(feature = "syslog_logging"), allow(dead_code))]
    pub syslog_facility: String,
    pub enable_c2_check: bool,
    pub enable_hash_check: bool,
    pub enable_string_check: bool,
    pub enable_filename_check: bool,
    pub enable_timeframe_check: bool,
    pub max_file_size_kb: u64,
    pub check_only_relevant_extensions: bool,
    pub relevant_extensions: HashSet<String>,
    pub excluded_dirs: HashSet<PathBuf>,
    pub forced_string_match_dirs: HashSet<PathBuf>,
    pub exclude_log_strings: HashSet<String>,
    pub min_hot_epoch: Option<u64>,
    pub max_hot_epoch: Option<u64>,
    pub debug: bool,
    pub num_threads: usize,
}

impl Config {
    pub fn load(scan_path: PathBuf) -> Result<Self> {
        // Use is_ok_and for boolean flags where default is false
        let debug = std::env::var("FENRIR_DEBUG")
            .is_ok_and(|v| v == "1" || v.to_lowercase() == "true");
        let log_to_syslog = std::env::var("FENRIR_LOG_TO_SYSLOG")
            .is_ok_and(|v| v == "1" || v.to_lowercase() == "true");
        let enable_timeframe_check = std::env::var("FENRIR_ENABLE_TIMEFRAME_CHECK")
            .is_ok_and(|v| v == "1" || v.to_lowercase() == "true");

        // Use map().unwrap_or(default) for boolean flags where default is true
        let log_to_file = std::env::var("FENRIR_LOG_TO_FILE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true); // Default ON
        let log_to_cmdline = std::env::var("FENRIR_LOG_TO_CMDLINE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true); // Default ON
        let enable_c2_check = std::env::var("FENRIR_ENABLE_C2_CHECK")
             .map(|v| v == "1" || v.to_lowercase() == "true")
             .unwrap_or(true);
        let enable_hash_check = std::env::var("FENRIR_ENABLE_HASH_CHECK")
             .map(|v| v == "1" || v.to_lowercase() == "true")
             .unwrap_or(true);
        let enable_string_check = std::env::var("FENRIR_ENABLE_STRING_CHECK")
             .map(|v| v == "1" || v.to_lowercase() == "true")
             .unwrap_or(true);
        let enable_filename_check = std::env::var("FENRIR_ENABLE_FILENAME_CHECK")
             .map(|v| v == "1" || v.to_lowercase() == "true")
             .unwrap_or(true);
        let check_only_relevant_extensions = std::env::var("FENRIR_CHECK_ONLY_RELEVANT_EXTENSIONS")
             .map(|v| v == "1" || v.to_lowercase() == "true")
             .unwrap_or(true);


        Ok(Config {
            scan_path,
            hash_ioc_file: PathBuf::from(
                std::env::var("FENRIR_HASH_IOC_FILE")
                    .unwrap_or_else(|_| DEFAULT_HASH_IOC_FILE.to_string()),
            ),
            string_ioc_file: PathBuf::from(
                std::env::var("FENRIR_STRING_IOC_FILE")
                    .unwrap_or_else(|_| DEFAULT_STRING_IOC_FILE.to_string()),
            ),
            filename_ioc_file: PathBuf::from(
                std::env::var("FENRIR_FILENAME_IOC_FILE")
                    .unwrap_or_else(|_| DEFAULT_FILENAME_IOC_FILE.to_string()),
            ),
            c2_ioc_file: PathBuf::from(
                std::env::var("FENRIR_C2_IOC_FILE")
                    .unwrap_or_else(|_| DEFAULT_C2_IOC_FILE.to_string()),
            ),
            log_file: Some(std::env::var("FENRIR_LOG_FILE_PATTERN")
                           .unwrap_or_else(|_| DEFAULT_LOG_FILE_PATTERN.to_string())),
            log_to_file,
            log_to_syslog,
            log_to_cmdline,
            syslog_facility: std::env::var("FENRIR_SYSLOG_FACILITY")
                .unwrap_or_else(|_| DEFAULT_SYSLOG_FACILITY.to_string()),
            enable_c2_check,
            enable_hash_check,
            enable_string_check,
            enable_filename_check,
            enable_timeframe_check,
            max_file_size_kb: std::env::var("FENRIR_MAX_FILE_SIZE_KB")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(DEFAULT_MAX_FILE_SIZE_KB),
            check_only_relevant_extensions,
            relevant_extensions: parse_env_hashset_string("FENRIR_RELEVANT_EXTENSIONS", &DEFAULT_RELEVANT_EXTENSIONS)?,
            excluded_dirs: parse_env_hashset_pathbuf("FENRIR_EXCLUDED_DIRS", &DEFAULT_EXCLUDED_DIRS)?,
            forced_string_match_dirs: parse_env_hashset_pathbuf("FENRIR_FORCED_STRING_MATCH_DIRS", &DEFAULT_FORCED_STRING_MATCH_DIRS)?,
            exclude_log_strings: parse_env_hashset_string("FENRIR_EXCLUDE_LOG_STRINGS", &DEFAULT_EXCLUDE_LOG_STRINGS)?,
            min_hot_epoch: parse_env_optional_u64("FENRIR_MIN_HOT_EPOCH")?,
            max_hot_epoch: parse_env_optional_u64("FENRIR_MAX_HOT_EPOCH")?,
            debug,
            num_threads: std::env::var("FENRIR_NUM_THREADS")
                 .ok()
                 .and_then(|s| s.parse::<usize>().ok())
                 .unwrap_or_else(num_cpus::get),
        })
    }

     pub fn get_current_log_file_path(&self) -> Result<Option<PathBuf>> {
        if !self.log_to_file || self.log_file.is_none() {
            return Ok(None);
        }
        let hostname = get_hostname()?;
        let date_str = chrono::Local::now().format("%Y%m%d").to_string();
        let pattern = self.log_file.as_ref().unwrap();
        let path_str = pattern
            .replace("{HOSTNAME}", &hostname)
            .replace("{DATE}", &date_str);
        Ok(Some(PathBuf::from(path_str)))
    }
}

fn parse_env_optional_u64(env_var: &str) -> Result<Option<u64>> {
    match std::env::var(env_var) {
        Ok(val_str) => {
            if val_str.is_empty() {
                Ok(None)
            } else {
                val_str.parse::<u64>()
                    .map(Some)
                    .map_err(|e| FenrirError::Config(format!("Invalid number format for {}: {}", env_var, e)))
            }
        },
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(FenrirError::Config(format!("Error reading env var {}: {}", env_var, e))),
    }
}

fn parse_env_hashset_string(env_var: &str, default: &HashSet<String>) -> Result<HashSet<String>> {
    match std::env::var(env_var) {
        Ok(val_str) => {
            if val_str.is_empty() {
                Ok(default.clone())
            } else {
                Ok(val_str.split(',').map(|s| s.trim().to_lowercase()).collect())
            }
        },
        Err(std::env::VarError::NotPresent) => Ok(default.clone()),
        Err(e) => Err(FenrirError::Config(format!("Error reading env var {}: {}", env_var, e))),
    }
}

fn parse_env_hashset_pathbuf(env_var: &str, default: &HashSet<PathBuf>) -> Result<HashSet<PathBuf>> {
     match std::env::var(env_var) {
        Ok(val_str) => {
             if val_str.is_empty() {
                Ok(default.clone())
            } else {
                Ok(val_str.split(',').map(|s| PathBuf::from(s.trim())).collect())
            }
        },
        Err(std::env::VarError::NotPresent) => Ok(default.clone()),
        Err(e) => Err(FenrirError::Config(format!("Error reading env var {}: {}", env_var, e))),
    }
}

pub fn get_epoch_seconds(time: SystemTime) -> Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| FenrirError::SystemInfo(format!("System time error: {}", e)))
}
