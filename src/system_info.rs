// fenrir-rust/src/system_info.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
// Возвращаем импорт макроса
use crate::log_info;
use lazy_static::lazy_static;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

pub fn get_hostname() -> Result<String> {
    hostname::get()?
        .into_string()
        .map_err(|os_str| FenrirError::SystemInfo(format!("Hostname is not valid UTF-8: {:?}", os_str)))
}

pub fn log_system_info(config: &Config) -> Result<()> {
    log_info!(config, "Gathering system information...");

    let hostname = get_hostname()?;
    log_info!(config, "HOSTNAME: {}", hostname);

    let ip_addresses = get_ip_addresses().unwrap_or_else(|e| {
        log_info!(config, "Could not get IP addresses: {}", e);
        "N/A".to_string()
    });
    log_info!(config, "IP: {}", ip_addresses);

    let os_release = get_os_release().unwrap_or_else(|e| {
         log_info!(config, "Could not get OS release info: {}", e);
        "N/A".to_string()
    });
    log_info!(config, "OS: {}", os_release);

    let os_issue = fs::read_to_string("/etc/issue")
        .map(|s| s.trim().replace('\n', "; "))
        .unwrap_or_else(|_| "N/A".to_string());
    log_info!(config, "ISSUE: {}", os_issue);

    let os_kernel = run_command("uname", &["-a"]).unwrap_or_else(|e| {
        log_info!(config, "Could not get kernel info: {}", e);
        "N/A".to_string()
    });
    log_info!(config, "KERNEL: {}", os_kernel);

    Ok(())
}

fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| FenrirError::UtilityNotFound { name: cmd.to_string(), source: e })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(FenrirError::CommandExecution {
            command: format!("{} {}", cmd, args.join(" ")),
            stderr: stderr.to_string(),
        })
    } else {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}


fn get_ip_addresses() -> Result<String> {
    let output = if cfg!(target_os = "linux") {
        Command::new("ip").arg("-4").arg("addr").output()
    } else {
         Command::new("ifconfig").output()
    };

    let output = output.map_err(|e| FenrirError::UtilityNotFound { name: "ip/ifconfig".to_string(), source: e })?;

     if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FenrirError::CommandExecution {
            command: "ip -4 addr / ifconfig".to_string(),
            stderr: stderr.to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();

    lazy_static! {
        static ref IP_RE: regex::Regex = regex::Regex::new(r"inet (?:addr:)?((?:\d{1,3}\.){3}\d{1,3})").unwrap();
    }
    for cap in IP_RE.captures_iter(&stdout) {
        if let Some(ip) = cap.get(1) {
            let ip_str = ip.as_str();
            if ip_str != "127.0.0.1" {
                ips.push(ip_str.to_string());
            }
        }
    }

    if ips.is_empty() {
        Ok("N/A".to_string())
    } else {
        Ok(ips.join(" "))
    }
}


fn get_os_release() -> Result<String> {
    let mut releases = Vec::new();
    match fs::read_dir("/etc") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                        if filename.ends_with("-release") || filename == "os-release" || filename == "lsb-release" {
                            if let Ok(content) = fs::read_to_string(&path) {
                                releases.push(content);
                            }
                        }
                    }
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok("N/A (/etc not found)".to_string());
        },
        Err(e) => return Err(FenrirError::FileAccess{ path: PathBuf::from("/etc"), source: e}),
    }


    if releases.is_empty() {
        Ok("N/A (No release files found)".to_string())
    } else {
        let mut unique_lines = std::collections::HashSet::new();
        for content in releases {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    unique_lines.insert(trimmed.to_string());
                }
            }
        }
        let mut sorted_lines: Vec<String> = unique_lines.into_iter().collect();
        sorted_lines.sort();
        Ok(sorted_lines.join("; "))
    }
}
