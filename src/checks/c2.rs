// fenrir-rust/src/checks/c2.rs
use crate::config::Config;
use crate::errors::{FenrirError, Result}; // Исправлен порядок
use crate::ioc::IocCollection;
// Возвращаем импорты макросов
use crate::{log_info, log_notice, log_warn};
use std::process::{Command, Stdio};

pub fn scan_c2(iocs: &IocCollection, config: &Config) -> Result<()> {
    if !config.enable_c2_check {
        log_info!(config, "C2 Check disabled by configuration.");
        return Ok(());
    }

    if Command::new("lsof").arg("-v").output().is_err() {
        // Отформатировано
        return Err(FenrirError::UtilityNotFound {
            name: "lsof".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "lsof command not found in PATH",
            ),
        });
    }

    log_info!(config, "[+] Scanning for C2 servers in 'lsof' output...");

    run_lsof_check(&["-i", "-n"], iocs, config, "lsof -i -n")?;
    run_lsof_check(&["-i"], iocs, config, "lsof -i")?;

    Ok(())
}

// Отформатировано
fn run_lsof_check(
    args: &[&str],
    iocs: &IocCollection,
    config: &Config,
    command_str: &str,
) -> Result<()> {
    let output = Command::new("lsof")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| FenrirError::UtilityNotFound {
            name: "lsof".to_string(),
            source: e,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        log_warn!(
            config,
            "{} command failed with status {}: {}",
            command_str,
            output.status,
            stderr
        );
        return Err(FenrirError::CommandExecution {
            command: command_str.to_string(),
            stderr,
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() {
            continue;
        }

        for c2_indicator in &iocs.c2_iocs {
            if trimmed_line.contains(c2_indicator) {
                log_warn!(
                    config,
                    "[!] C2 server found in {} output SERVER: {} LSOF_LINE: {}",
                    command_str,
                    c2_indicator,
                    trimmed_line
                );
            }
        }

        if (trimmed_line.starts_with("bash ") || trimmed_line.starts_with("sh "))
            && !trimmed_line.contains("127.0.0.1")
            && !trimmed_line.contains("::1")
        {
            log_notice!(
                config,
                "[!] Shell found in {} output - could be a back connect shell LSOF_LINE: {}",
                command_str,
                trimmed_line
            );
        }
    }
    Ok(())
}
