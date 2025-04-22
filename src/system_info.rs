// fenrir-rust/src/system_info.rs
use crate::config::Config;
use crate::errors::{Result, FenrirError};
use crate::logger::log_info; // Use macro
use std::fs;
use std::io;
use std::process::Command;
use std::path::PathBuf; // Added import

pub fn log_system_info(config: &Config) -> Result<()> {
    // ... (rest of the function remains the same) ...
    log_info!(config, "Gathering system information...");

    // Hostname
    let hostname = hostname::get()?
        .into_string()
        .map_err(|os_str| FenrirError::SystemInfo(format!("Hostname is not valid UTF-8: {:?}", os_str)))?;
    log_info!(config, "HOSTNAME: {}", hostname);

    // IP Addresses (using 'ip' command on Linux, 'ifconfig' as fallback/macOS)
    let ip_addresses = get_ip_addresses(config).unwrap_or_else(|e| { // Pass config for logging
        log_info!(config, "Could not get IP addresses: {}", e);
        "N/A".to_string()
    });
    log_info!(config, "IP: {}", ip_addresses);

    // OS Release (/etc/*release)
    let os_release = get_os_release(config).unwrap_or_else(|e| { // Pass config
         log_info!(config, "Could not get OS release info: {}", e);
        "N/A".to_string()
    });
    log_info!(config, "OS: {}", os_release);

     // Issue (/etc/issue)
    let os_issue = fs::read_to_string("/etc/issue")
        .map(|s| s.trim().replace('\n', "; "))
        .unwrap_or_else(|_| "N/A".to_string());
    log_info!(config, "ISSUE: {}", os_issue);

    // Kernel (uname -a)
    let os_kernel = run_command("uname", &["-a"]).unwrap_or_else(|e| {
        log_info!(config, "Could not get kernel info: {}", e);
        "N/A".to_string()
    });
    log_info!(config, "KERNEL: {}", os_kernel);


    Ok(())
}

// ... run_command remains the same ...
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


fn get_ip_addresses(config: &Config) -> Result<String> { // Added config param
    let output = if cfg!(target_os = "linux") {
        Command::new("ip").arg("-4").arg("addr").output() // Try 'ip' command first on Linux
    } else if cfg!(target_os = "macos") || cfg!(target_os = "freebsd") { // Add other Unix?
         Command::new("ifconfig").output() // Fallback or for other Unix-like (macOS)
    } else {
        // Handle Windows? 'ipconfig' - currently not implemented in script either for IP gathering
        return Ok("N/A (Platform not supported for IP)".to_string());
    };

    let output = output.map_err(|e| FenrirError::UtilityNotFound { name: "ip/ifconfig".to_string(), source: e })?;

     if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Log warning but don't error out
        log_warn!(config, "ip/ifconfig command failed: {}", stderr);
        return Ok("N/A (Command failed)".to_string());
        // return Err(FenrirError::CommandExecution {
        //     command: "ip -4 addr / ifconfig".to_string(),
        //     stderr: stderr.to_string(),
        // });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();
    // Simple regex to find IPv4 addresses (adjust as needed for IPv6 or robustness)
    // Handles Linux 'inet ' and macOS 'inet ' formats.
    let re = regex::Regex::new(r"inet (?:addr:)?((?:\d{1,3}\.){3}\d{1,3})").unwrap();
    for cap in re.captures_iter(&stdout) {
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


fn get_os_release(config: &Config) -> Result<String> { // Added config param
    let mut releases = Vec::new();
    // Check common locations
    let release_files = ["/etc/os-release", "/etc/lsb-release"]; // Add more like /etc/redhat-release?
    let release_dirs = ["/etc"];

    for file_path in release_files {
         match fs::read_to_string(file_path) {
             Ok(content) => releases.push(content),
             Err(e) if e.kind() == io::ErrorKind::NotFound => {} // Ignore if specific file not found
             Err(e) => log_warn!(config, "Error reading release file {}: {}", file_path, e), // Log other errors
         }
    }

    for dir_path in release_dirs {
         match fs::read_dir(dir_path) {
            Ok(entries) => {
                for entry_res in entries {
                    if let Ok(entry) = entry_res {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                                // Look for files ending in -release, but avoid duplicates from specific paths above
                                if filename.ends_with("-release") && !release_files.contains(&path.to_str().unwrap_or_default()) {
                                     match fs::read_to_string(&path) {
                                         Ok(content) => releases.push(content),
                                         Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                                         Err(e) => log_warn!(config, "Error reading release file {}: {}", path.display(), e),
                                     }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                 log_warn!(config, "Release directory {} not found.", dir_path);
            },
             Err(e) => log_warn!(config, "Error reading release directory {}: {}", dir_path, e),
        }
    }


    if releases.is_empty() {
        Ok("N/A (No release files found)".to_string())
    } else {
        // Collect unique lines from all release files
        let mut unique_lines = std::collections::HashSet::new();
        for content in releases {
            for line in content.lines() {
                let trimmed = line.trim();
                // Filter out comments and empty lines
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    // Extract key info like PRETTY_NAME or NAME/VERSION
                    if let Some((key, value)) = trimmed.split_once('=') {
                         let key = key.trim();
                         let value = value.trim().trim_matches('"'); // Remove quotes
                         if ["PRETTY_NAME", "NAME", "VERSION"].contains(&key) && !value.is_empty() {
                            unique_lines.insert(format!("{}: {}", key, value));
                         }
                    } else if !trimmed.contains('=') {
                         // If no '=', assume it's content from e.g. redhat-release
                         unique_lines.insert(trimmed.to_string());
                    }
                }
            }
        }
        if unique_lines.is_empty() {
            Ok("N/A (No useful info in release files)".to_string())
        } else {
            let mut sorted_lines: Vec<String> = unique_lines.into_iter().collect();
            sorted_lines.sort();
            Ok(sorted_lines.join("; "))
        }
    }
}
