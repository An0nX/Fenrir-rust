// fenrir-rust/src/errors.rs
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FenrirError {
    #[error("Configuration Error: {0}")]
    Config(String),

    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File Access Error on path '{path}': {source}")]
    FileAccess {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read IOC file '{path}': {source}")]
    IocRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid IOC format in file '{path}' on line: {details}")]
    IocFormat { path: PathBuf, details: String },

    #[allow(dead_code)]
    #[error("Failed to parse argument: {0}")]
    Argument(String),

    #[error("Required utility '{name}' not found or failed to execute: {source}")]
    UtilityNotFound {
        name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to execute command '{command}': {stderr}")]
    CommandExecution { command: String, stderr: String },

    #[allow(dead_code)]
    // Отформатировано
    #[error("Failed to parse command output for '{command}': {details}")]
    CommandOutputParse { command: String, details: String },

    #[allow(dead_code)]
    #[error("Hashing error: {0}")]
    Hashing(String),

    #[error("String matching error: {0}")]
    StringMatching(String),

    #[error("Logging setup failed: {0}")]
    LoggingSetup(String),

    #[error("System information retrieval failed: {0}")]
    SystemInfo(String),

    // Отформатировано (удалена пустая строка)
    #[error("Date/Time parsing or conversion error: {0}")]
    DateTimeError(#[from] chrono::ParseError),

    #[error("Integer conversion error: {0}")]
    IntConversion(#[from] std::num::ParseIntError),

    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Walkdir error: {0}")]
    Walkdir(#[from] walkdir::Error),
    // Отформатировано (удалена пустая строка)
}

pub type Result<T> = std::result::Result<T, FenrirError>;
