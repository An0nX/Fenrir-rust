// fenrir-rust/src/checks/timeframe.rs
use crate::config::{get_epoch_seconds, Config};
use crate::errors::{Result, FenrirError};
// Import macro from crate root
use crate::log_warn;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

pub fn check_timeframe(path: &Path, config: &Config) -> Result<()> {
    if !config.enable_timeframe_check {
        return Ok(());
    }

    if config.min_hot_epoch.is_none() || config.max_hot_epoch.is_none() {
         // Use tracing directly if logger might not be fully set up, or macro if safe
         tracing::warn!("Timeframe check enabled, but min/max epoch not set. Skipping timeframe check for {}", path.display());
        return Ok(());
    }

    let min_epoch = config.min_hot_epoch.unwrap();
    let max_epoch = config.max_hot_epoch.unwrap();

    let metadata = fs::metadata(path).map_err(|e| FenrirError::FileAccess { path: path.to_path_buf(), source: e })?;

    let created_time = metadata.created().ok();
    let modified_time = metadata.modified().ok();

    let mut matched = false;
    let mut epoch_value = 0;

    if let Some(time) = created_time {
        if check_time(time, min_epoch, max_epoch)? {
            matched = true;
            epoch_value = get_epoch_seconds(time)?;
        }
    }

    if !matched {
        if let Some(time) = modified_time {
             if check_time(time, min_epoch, max_epoch)? {
                matched = true;
                epoch_value = get_epoch_seconds(time)?;
            }
        }
    }

    if matched {
        log_warn!(config, "[!] File changed/created in hot time frame FILE: {} EPOCH: {}", path.display(), epoch_value); // Use macro directly
    }

    Ok(())
}

fn check_time(time: SystemTime, min_epoch: u64, max_epoch: u64) -> Result<bool> {
    let file_epoch = get_epoch_seconds(time)?;
    Ok(file_epoch > min_epoch && file_epoch < max_epoch)
}
