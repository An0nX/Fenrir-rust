// fenrir-rust/src/checks/filename.rs
use crate::config::Config;
use crate::ioc::IocCollection;
// Возвращаем импорт макроса
use crate::log_warn;
use std::path::Path;

pub fn check_filename(path: &Path, iocs: &IocCollection, config: &Config) {
    if !config.enable_filename_check {
        return;
    }

    if let Some(path_str) = path.to_str() {
         for ioc_filename in &iocs.filename_iocs {
            if path_str.contains(ioc_filename) {
                log_warn!(config, "[!] Filename match found FILE: {} INDICATOR: {}", path.display(), ioc_filename);
            }
        }
    } else {
         // Теперь можно вызывать напрямую, т.к. макрос импортирован
         log_warn!(config, "Skipping filename check for non-UTF8 path: {:?}", path);
    }
}
