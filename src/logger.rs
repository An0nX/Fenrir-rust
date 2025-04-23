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
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_level(true)
            .with_ansi(true)
            .with_span_events(FmtSpan::NONE)
            .without_time()
             .with_filter(cmd_level);
        layers.push(cmd_layer.boxed());
    }

    // File Logger
    if config.log_to_file {
         if let Some(log_path) = config.get_current_log_file_path()? {
            let file_appender = tracing_appender::rolling::daily(
                log_path.parent().unwrap_or_else(|| Path::new(".")),
                log_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("fenrir.log")),
            );
            let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);

            *LOG_GUARD.lock().unwrap() = Some(guard);

            let file_level = if config.debug { LevelFilter::DEBUG } else { LevelFilter::INFO };
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(non_blocking_appender)
                .with_ansi(false)
                .with_target(false)
                .with_level(true)
                .with_span_events(FmtSpan::NONE)
                .with_filter(file_level);
            layers.push(file_layer.boxed());
        } else {
             eprintln!("Warning: File logging enabled but could not determine log file path.");
        }
    }

    // Syslog Logger (Optional Feature)
    #[cfg(feature = "syslog_logging")]
    {
        if config.log_to_syslog {
            let syslog_level = if config.debug { LevelFilter::DEBUG } else { LevelFilter::INFO };
             let level_mapper = |level: &tracing::Level| -> syslog::Severity {
                 match *level {
                     tracing::Level::ERROR => syslog::Severity::LOG_ERR,
                     tracing::Level::WARN => syslog::Severity::LOG_WARNING,
                     tracing::Level::INFO => syslog::Severity::LOG_INFO,
                     tracing::Level::DEBUG => syslog::Severity::LOG_DEBUG,
                     tracing::Level::TRACE => syslog::Severity::LOG_DEBUG,
                 }
             };

             let facility = match config.syslog_facility.to_lowercase().as_str() {
                  "kern" => syslog::Facility::LOG_KERN, "user" => syslog::Facility::LOG_USER,
                  "mail" => syslog::Facility::LOG_MAIL, "daemon" => syslog::Facility::LOG_DAEMON,
                  "auth" => syslog::Facility::LOG_AUTH, "syslog" => syslog::Facility::LOG_SYSLOG,
                  "lpr" => syslog::Facility::LOG_LPR, "news" => syslog::Facility::LOG_NEWS,
                  "uucp" => syslog::Facility::LOG_UUCP, "cron" => syslog::Facility::LOG_CRON,
                  "authpriv" => syslog::Facility::LOG_AUTHPRIV, "ftp" => syslog::Facility::LOG_FTP,
                  "local0" => syslog::Facility::LOG_LOCAL0, "local1" => syslog::Facility::LOG_LOCAL1,
                  "local2" => syslog::Facility::LOG_LOCAL2, "local3" => syslog::Facility::LOG_LOCAL3,
                  "local4" => syslog::Facility::LOG_LOCAL4, "local5" => syslog::Facility::LOG_LOCAL5,
                  "local6" => syslog::Facility::LOG_LOCAL6, "local7" => syslog::Facility::LOG_LOCAL7,
                  _ => {
                      eprintln!("Warning: Invalid syslog facility '{}', using LOG_USER.", config.syslog_facility);
                      syslog::Facility::LOG_USER
                  }
              };

             let formatter = syslog::Formatter3164 {
                  facility, hostname: None, process: "fenrir-rust".into(), pid: 0,
              };

            match syslog::unix(formatter) {
                Ok(writer) => {
                    let syslog_layer = tracing_syslog::SyslogLayer::new( writer, syslog_level, level_mapper)
                         .map_err(|e| FenrirError::LoggingSetup(format!("Syslog layer init failed: {}", e)))?;
                     layers.push(syslog_layer.boxed());
                 },
                 Err(e) => {
                     eprintln!("Error: Failed to connect to syslog: {}", e);
                 }
            }
        }
    }
    #[cfg(not(feature = "syslog_logging"))]
    {
        if config.log_to_syslog {
             eprintln!("Warning: Syslog logging requested, but the 'syslog_logging' feature is not enabled.");
        }
    }


    tracing_subscriber::registry()
        .with(layers)
        .try_init()
        .map_err(|e| FenrirError::LoggingSetup(format!("Failed to initialize logger: {}", e)))?;

    Ok(())
}

pub fn should_log(message: &str, config: &Config) -> bool {
    !config.exclude_log_strings.iter().any(|excluded| message.contains(excluded))
}

// --- Corrected Macro Definitions ---
// Wrap the logic in a block `{}` so the macro expands to something usable as a statement.
// Remove trailing semicolon inside format!

#[macro_export]
macro_rules! log_info {
    ($config:expr, $($arg:tt)*) => {
        { // Start block
            let msg = format!($($arg)*); // No semicolon needed here
            if $crate::logger::should_log(&msg, $config) {
                tracing::info!("{}", msg) // No semicolon needed here
            }
        } // End block
    };
}

#[macro_export]
macro_rules! log_warn {
     ($config:expr, $($arg:tt)*) => {
         { // Start block
             let msg = format!($($arg)*);
             if $crate::logger::should_log(&msg, $config) {
                 tracing::warn!("{}", msg)
             }
         } // End block
    };
}

#[macro_export]
macro_rules! log_error {
     ($config:expr, $($arg:tt)*) => {
         { // Start block
            let msg = format!($($arg)*);
            // Error messages usually bypass exclusion filters
            tracing::error!("{}", msg)
         } // End block
    };
}

#[macro_export]
macro_rules! log_notice {
    ($config:expr, $($arg:tt)*) => {
         { // Start block
            let msg = format!($($arg)*);
            if $crate::logger::should_log(&msg, $config) {
                tracing::info!("NOTICE: {}", msg) // Prefixing manually for clarity
            }
         } // End block
    };
}


#[macro_export]
macro_rules! log_debug {
    ($config:expr, $($arg:tt)*) => {
        { // Start block
            let msg = format!($($arg)*);
            if $config.debug && $crate::logger::should_log(&msg, $config) {
                tracing::debug!("{}", msg)
            }
        } // End block
    };
}

// Removed redundant pub(crate) use lines
// pub(crate) use log_debug;
// pub(crate) use log_error;
// pub(crate) use log_info;
// pub(crate) use log_warn;
// pub(crate) use log_notice;
