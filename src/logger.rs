// fenrir-rust/src/logger.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use std::path::Path;
use std::sync::Mutex;
use tracing::metadata::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use tracing_appender::non_blocking::WorkerGuard;

// Keep guard until end of program
static LOG_GUARD: Mutex<Option<WorkerGuard>> = Mutex::new(None);

pub fn setup_logging(config: &Config) -> Result<()> {
    let mut layers = Vec::new();

    // Console Logger
    if config.log_to_cmdline {
        let cmd_level = if config.debug { LevelFilter::DEBUG } else { LevelFilter::INFO };
        let cmd_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr) // Write to stderr like the script
            .with_target(false) // Don't print module paths
            .with_level(true)
            .with_ansi(true) // Enable colors if terminal supports it
            .with_span_events(FmtSpan::NONE) // No span events
            .without_time() // Mimic script's simple output
             .with_filter(cmd_level);
        layers.push(cmd_layer.boxed());
    }

    // File Logger
    if config.log_to_file {
         if let Some(log_path) = config.get_current_log_file_path()? {
            let file_appender = tracing_appender::rolling::daily(
                log_path.parent().unwrap_or_else(|| Path::new(".")), // Log dir
                log_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("fenrir.log")), // Log filename
            );
            let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);

            // Store the guard to prevent logs from being dropped prematurely
            *LOG_GUARD.lock().unwrap() = Some(guard);

            let file_level = if config.debug { LevelFilter::DEBUG } else { LevelFilter::INFO };
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(non_blocking_appender)
                .with_ansi(false) // No ANSI colors in file
                .with_target(false)
                .with_level(true)
                .with_span_events(FmtSpan::NONE)
                .with_filter(file_level);
            layers.push(file_layer.boxed());
        } else {
             tracing::warn!("File logging enabled but could not determine log file path.");
        }
    }

    // Syslog Logger (Optional Feature)
    #[cfg(feature = "syslog_logging")]
    {
        if config.log_to_syslog {
            let syslog_level = if config.debug { LevelFilter::DEBUG } else { LevelFilter::INFO };
             // Map tracing level to syslog level (adjust mapping as needed)
             let level_mapper = |level: &tracing::Level| -> syslog::Severity {
                 match *level {
                     tracing::Level::ERROR => syslog::Severity::LOG_ERR,
                     tracing::Level::WARN => syslog::Severity::LOG_WARNING,
                     tracing::Level::INFO => syslog::Severity::LOG_INFO,
                     tracing::Level::DEBUG => syslog::Severity::LOG_DEBUG,
                     tracing::Level::TRACE => syslog::Severity::LOG_DEBUG, // Syslog doesn't have trace
                 }
             };

             // Parse facility string
             let facility = match config.syslog_facility.to_lowercase().as_str() {
                  "kern" => syslog::Facility::LOG_KERN,
                  "user" => syslog::Facility::LOG_USER,
                  "mail" => syslog::Facility::LOG_MAIL,
                  "daemon" => syslog::Facility::LOG_DAEMON,
                  "auth" => syslog::Facility::LOG_AUTH,
                  "syslog" => syslog::Facility::LOG_SYSLOG,
                  "lpr" => syslog::Facility::LOG_LPR,
                  "news" => syslog::Facility::LOG_NEWS,
                  "uucp" => syslog::Facility::LOG_UUCP,
                  "cron" => syslog::Facility::LOG_CRON,
                  "authpriv" => syslog::Facility::LOG_AUTHPRIV,
                  "ftp" => syslog::Facility::LOG_FTP,
                  "local0" => syslog::Facility::LOG_LOCAL0,
                  "local1" => syslog::Facility::LOG_LOCAL1,
                  "local2" => syslog::Facility::LOG_LOCAL2,
                  "local3" => syslog::Facility::LOG_LOCAL3,
                  "local4" => syslog::Facility::LOG_LOCAL4,
                  "local5" => syslog::Facility::LOG_LOCAL5,
                  "local6" => syslog::Facility::LOG_LOCAL6,
                  "local7" => syslog::Facility::LOG_LOCAL7,
                  _ => {
                      tracing::warn!("Invalid syslog facility '{}', using LOG_USER.", config.syslog_facility);
                      syslog::Facility::LOG_USER
                  }
              };

             let formatter = syslog::Formatter3164 {
                  facility,
                  hostname: None, // Let syslog add it
                  process: "fenrir-rust".into(), // TODO: Get executable name?
                  pid: 0, // Let syslog add it
              };

            match syslog::unix(formatter) {
                Ok(writer) => {
                    let syslog_layer = tracing_syslog::SyslogLayer::new(
                        writer,
                        syslog_level,
                        level_mapper, // Pass the level mapper closure
                    ).map_err(|e| FenrirError::LoggingSetup(format!("Syslog layer init failed: {}", e)))?;
                     layers.push(syslog_layer.boxed());
                 },
                 Err(e) => {
                     tracing::error!("Failed to connect to syslog: {}", e);
                     // Don't push the layer, maybe log to stderr?
                 }
            }
        }
    }
    #[cfg(not(feature = "syslog_logging"))]
    {
        if config.log_to_syslog {
            tracing::warn!("Syslog logging requested, but the 'syslog_logging' feature is not enabled.");
        }
    }


    // Initialize the combined subscriber
    tracing_subscriber::registry()
        .with(layers)
        .try_init()
        .map_err(|e| FenrirError::LoggingSetup(format!("Failed to initialize logger: {}", e)))?;

    Ok(())
}

// Log filtering helper (to replace script's EXCLUDE_STRINGS)
pub fn should_log(message: &str, config: &Config) -> bool {
    for excluded in &config.exclude_log_strings {
        if message.contains(excluded) {
            return false;
        }
    }
    true
}

// --- Macros for convenient logging respecting exclusions ---
// Note: Using macros requires careful handling of arguments if they have side effects.

#[macro_export]
macro_rules! log_info {
    ($config:expr, $($arg:tt)*) => {
        let msg = format!($($arg)*);
        if $crate::logger::should_log(&msg, $config) {
            tracing::info!("{}", msg);
        }
    };
}

#[macro_export]
macro_rules! log_warn {
     ($config:expr, $($arg:tt)*) => {
        let msg = format!($($arg)*);
        if $crate::logger::should_log(&msg, $config) {
            tracing::warn!("{}", msg); // Prefix handled by logger automatically
        }
    };
}

#[macro_export]
macro_rules! log_error {
     ($config:expr, $($arg:tt)*) => {
        let msg = format!($($arg)*);
         // Error messages usually bypass exclusion filters
         tracing::error!("{}", msg);
    };
}

#[macro_export]
macro_rules! log_debug {
    ($config:expr, $($arg:tt)*) => {
        // Debug messages might also bypass exclusions if needed, or apply filter
        let msg = format!($($arg)*);
        if $config.debug && $crate::logger::should_log(&msg, $config) {
            tracing::debug!("{}", msg);
        }
    };
}

// Re-export for convenience within the crate
pub(crate) use log_debug;
pub(crate) use log_error;
pub(crate) use log_info;
pub(crate) use log_warn;
