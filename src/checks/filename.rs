// fenrir-rust/src/checks/filename.rs
use crate::config::Config;
use crate::ioc::IocCollection;
use crate::logger::log_warn; // Use the macro
use std::path::Path;

pub fn check_filename(path: &Path, iocs: &IocCollection, config: &Config) {
    if !config.enable_filename_check {
        return;
    }

    // Convert path to string for substring matching, handling potential non-UTF8 paths
    if let Some(path_str) = path.to_str() {
         for ioc_filename in &iocs.filename_iocs {
            // Mimic bash's substring check: "${path/$ioc_filename}" != "$path"
            if path_str.contains(ioc_filename) {
                log_warn!(config, "[!] Filename match found FILE: {} INDICATOR: {}", path.display(), ioc_filename);
                // Could break after first match if desired
            }
        }
    } else {
         log_warn!(config, "Skipping filename check for non-UTF8 path: {:?}", path);
    }
}
