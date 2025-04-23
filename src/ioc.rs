// fenrir-rust/src/ioc.rs
use crate::config::Config;
use crate::errors::{FenrirError, Result};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path; // Removed PathBuf from here

#[derive(Debug, Clone)]
pub struct IocCollection {
    pub hashes: HashMap<String, String>,
    pub string_ioc_matcher: Option<AhoCorasick>,
    pub string_ioc_list: Vec<String>,
    pub filename_iocs: HashSet<String>,
    pub c2_iocs: HashSet<String>,
}

impl IocCollection {
    pub fn load(config: &Config) -> Result<Self> {
        let hashes = load_hash_iocs(&config.hash_ioc_file)?;
        let (string_ioc_list, c2_iocs) = load_string_and_c2_iocs(
                                              &config.string_ioc_file,
                                              &config.c2_ioc_file
                                          )?;
        let filename_iocs = load_filename_iocs(&config.filename_ioc_file)?;

        let all_strings_for_matcher: Vec<&str> = string_ioc_list.iter()
                                                  .map(AsRef::as_ref)
                                                  .chain(c2_iocs.iter().map(AsRef::as_ref))
                                                  .collect();

        let string_ioc_matcher = if !all_strings_for_matcher.is_empty() {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .ascii_case_insensitive(false)
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

fn read_lines(path: &Path) -> Result<impl Iterator<Item = Result<String>>> {
    let file = File::open(path).map_err(|e| FenrirError::IocRead { path: path.to_path_buf(), source: e })?;
    let reader = BufReader::new(file);
    Ok(reader.lines().map(|line_res| line_res.map_err(FenrirError::Io)))
}

fn load_hash_iocs(path: &Path) -> Result<HashMap<String, String>> {
    let mut iocs = HashMap::new();
    for (line_num, line_res) in read_lines(path)?.enumerate() {
        let line = line_res?;
        let trimmed_line = line.trim();

        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }
        match trimmed_line.split_once(';') {
            Some((hash, description)) => {
                let hash_trimmed = hash.trim().to_lowercase();
                 if (hash_trimmed.len() == 32 || hash_trimmed.len() == 40 || hash_trimmed.len() == 64)
                    && hash_trimmed.chars().all(|c| c.is_ascii_hexdigit())
                 {
                    iocs.insert(hash_trimmed, description.trim().to_string());
                } else {
                    return Err(FenrirError::IocFormat {
                        path: path.to_path_buf(), // PathBuf needed here
                        details: format!("L{}: Invalid hash format '{}'", line_num + 1, hash_trimmed),
                     });
                }
            }
            None => {
                return Err(FenrirError::IocFormat {
                    path: path.to_path_buf(), // PathBuf needed here
                    details: format!("L{}: Missing ';' separator in line '{}'", line_num + 1, trimmed_line),
                });
            }
        }
    }
    Ok(iocs)
}

fn load_filename_iocs(path: &Path) -> Result<HashSet<String>> {
    let mut iocs = HashSet::new();
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

    for line_res in read_lines(string_path)? {
        let line = line_res?.trim().to_string();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        string_iocs.push(line);
    }

    for line_res in read_lines(c2_path)? {
        let line = line_res?.trim().to_string();
         if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        c2_iocs.insert(line);
    }

    Ok((string_iocs, c2_iocs))
}
