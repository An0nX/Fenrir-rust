// fenrir-rust/src/checks/c2.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::ioc::IocCollection;
// Ensure correct macros are imported (log_notice was missing)
use crate::logger::{log_info, log_notice, log_warn};
use std::process::{Command, Stdio};

// WARNING: This relies on the external `lsof` command. Ensure it's installed
// and accessible in the system's PATH where this Rust binary runs.
// Consider this a security trade-off for feature parity with the original script.
// A pure Rust implementation would require platform-specific APIs (e.g., /proc, sysctl).

pub fn scan_c2(iocs: &IocCollection, config: &Config) -> Result<()> {
    if !config.enable_c2_check {
        log_info!(config, "C2 Check disabled by configuration.");
        return Ok(());
    }

    // Check if lsof exists first
    if Command::new("lsof").arg("-v").output().is_err() {
         return Err(FenrirError::UtilityNotFound {
             name: "lsof".to_string(),
             source: std::io::Error::new(std::io::ErrorKind::NotFound, "lsof command not found in PATH"),
         });
    }


    log_info!(config, "[+] Scanning for C2 servers in 'lsof' output...");

    // Run lsof -i -n (no name resolution)
    run_lsof_check(&["-i", "-n"], iocs, config, "lsof -i -n")?;

    // Run lsof -i (with name resolution)
    run_lsof_check(&["-i"], iocs, config, "lsof -i")?;

    Ok(())
}

fn run_lsof_check(args: &[&str], iocs: &IocCollection, config: &Config, command_str: &str) -> Result<()> {
    let output = Command::new("lsof")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) // Capture stderr too
        .output()
        .map_err(|e| FenrirError::UtilityNotFound { name: "lsof".to_string(), source: e })?;

     if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        // Log non-zero exit code but don't necessarily fail the whole scan? Maybe return error.
         log_warn!(config, "{} command failed with status {}: {}", command_str, output.status, stderr);
         return Err(FenrirError::CommandExecution { command: command_str.to_string(), stderr });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() {
            continue;
        }

        // 1. C2 Check
        for c2_indicator in &iocs.c2_iocs {
            // Simple substring check like the script
            if trimmed_line.contains(c2_indicator) {
                 log_warn!(config, "[!] C2 server found in {} output SERVER: {} LSOF_LINE: {}", command_str, c2_indicator, trimmed_line);
                 // Optimization: could break inner loop once a C2 is found for this line
            }
        }

        // 2. Shell Check (only for '-n' run potentially? Script does it for both)
        // Check if line starts with "bash " or "sh " and doesn't contain localhost
        // This check is fragile as process names can vary.
        if trimmed_line.starts_with("bash ") || trimmed_line.starts_with("sh ") {
            if !trimmed_line.contains("127.0.0.1") && !trimmed_line.contains("::1") {
                 log_notice!(config, "[!] Shell found in {} output - could be a back connect shell LSOF_LINE: {}", command_str, trimmed_line);
            }
        }
    }
    Ok(())
}
