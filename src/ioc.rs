// fenrir-rust/src/ioc.rs
use crate::config::Config; // Corrected: use instead of uuse
use crate::errors::{FenrirError, Result};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path; // Corrected: Removed unused PathBuf

#[derive(Debug, Clone)]
pub struct IocCollection {
    // Hashes: Store as lowercase hex strings
    pub hashes: HashMap<String, String>, // Key: hash (lowercase), Value: description
    pub string_ioc_matcher: Option<AhoCorasick>, // Precompiled matcher for strings + C2
    pub string_ioc_list: Vec<String>, // Keep original strings for reporting matches
    pub filename_iocs: HashSet<String>, // Store lowercase filenames/paths
    pub c2_iocs: HashSet<String>,       // Store C2 hosts/IPs
}

impl IocCollection {
    pub fn load(config: &Config) -> Result<Self> {
        let hashes = load_hash_iocs(&config.hash_ioc_file)?;
        let (string_ioc_list, c2_iocs) = load_string_and_c2_iocs(
                                              &config.string_ioc_file,
                                              &config.c2_ioc_file
                                          )?;
        let filename_iocs = load_filename_iocs(&config.filename_ioc_file)?;

        // Combine strings and C2 IOCs for the Aho-Corasick matcher
        let all_strings_for_matcher: Vec<&str> = string_ioc_list.iter()
                                                  .map(AsRef::as_ref)
                                                  .chain(c2_iocs.iter().map(AsRef::as_ref))
                                                  .collect();

        let string_ioc_matcher = if !all_strings_for_matcher.is_empty() {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .ascii_case_insensitive(false) // Match case-sensitively
                    .build(&all_strings_for_matcher)
                    .map_err(|e| FenrirError::StringMatching(format!("AhoCorasick build error: {}", e)))?
            )
        } else {
            None
        };

        Ok(IocCollection {
            hashes,
            string_ioc_matcher,
            string_ioc_list,
            filename_iocs,
            c2_iocs,
        })
    }
}


// --- Helper Functions ---

fn read_lines(path: &Path) -> Result<impl Iterator<Item = Result<String>>> {
    let file = File::open(path).map_err(|e| FenrirError::IocRead { path: path.to_path_buf(), source: e })?;
    let reader = BufReader::new(file);
    Ok(reader.lines().map(|line_res| line_res.map_err(FenrirError::Io)))
}

fn load_hash_iocs(path: &Path) -> Result<HashMap<String, String>> {
    let mut iocs = HashMap::new();
    if !path.exists() {
        tracing::warn!("Hash IOC file not found: {}", path.display());
        return Ok(iocs); // Return empty map if file doesn't exist
    }
    for line_res in read_lines(path)? {
        let line = line_res?.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((hash, description)) = line.split_once(';') {
            let hash_trimmed = hash.trim().to_lowercase();
             if (hash_trimmed.len() == 32 || hash_trimmed.len() == 40 || hash_trimmed.len() == 64)
                && hash_trimmed.chars().all(|c| c.is_ascii_hexdigit())
             {
                iocs.insert(hash_trimmed, description.trim().to_string());
            } else {
                 tracing::warn!("Skipping invalid hash IOC line in {:?}: {}", path, line);
            }
        } else {
             tracing::warn!("Skipping invalid hash IOC line format (missing ';') in {:?}: {}", path, line);
        }
    }
    Ok(iocs)
}

fn load_filename_iocs(path: &Path) -> Result<HashSet<String>> {
    let mut iocs = HashSet::new();
    if !path.exists() {
        tracing::warn!("Filename IOC file not found: {}", path.display());
        return Ok(iocs);
    }
    for line_res in read_lines(path)? {
        let line = line_res?.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        iocs.insert(line);
    }
    Ok(iocs)
}

fn load_string_and_c2_iocs(string_path: &Path, c2_path: &Path) -> Result<(Vec<String>, HashSet<String>)> {
    let mut string_iocs = Vec::new();
    let mut c2_iocs = HashSet::new();

    // Load strings
    if !string_path.exists() {
        tracing::warn!("String IOC file not found: {}", string_path.display());
    } else {
        for line_res in read_lines(string_path)? {
            let line = line_res?.trim().to_string();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            string_iocs.push(line);
        }
    }

    // Load C2s
    if !c2_path.exists() {
         tracing::warn!("C2 IOC file not found: {}", c2_path.display());
    } else {
        for line_res in read_lines(c2_path)? {
            let line = line_res?.trim().to_string();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            c2_iocs.insert(line);
        }
    }

    Ok((string_iocs, c2_iocs))
}
