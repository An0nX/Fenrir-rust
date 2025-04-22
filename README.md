# Fenrir Rust

## Secure Rust Rewrite of the Simple Bash IOC Scanner

This project is a complete rewrite of the original Fenrir Bash IOC scanner, developed by Florian Roth, into the Rust programming language. The primary goals of this rewrite are **maximum security, robustness, and portability**, while maintaining the core IOC scanning functionality.

**Original Project:** [Fenrir by Florian Roth](https://github.com/Neo23x0/Fenrir) (Please refer to the original for context and IOC definitions).

**Version:** 0.9.0-log4shell-rust (Matches logic from original script version)

## Features

*   **IOC Scanning:** Scans Linux, macOS, and Windows systems for Indicators of Compromise (IOCs):
    *   **Hashes:** MD5, SHA1, SHA256 checks against `hash-iocs.txt`.
    *   **File Names:** Substring checks against `filename-iocs.txt`.
    *   **Strings:** Fast, multi-string checks (using Aho-Corasick) within files against `string-iocs.txt` and `c2-iocs.txt`. Supports plain text and compressed logs (`.gz`, `.bz2`) in specific directories (e.g., `/var/log`).
    *   **C2 Servers:** Checks network connections for C2 indicators from `c2-iocs.txt` by utilizing the external `lsof` command (on Linux/macOS). Also checks for suspicious shell processes in `lsof` output.
    *   **Hot Time Frame:** Identifies files created or modified within a specific timestamp range (configure via environment variables).
*   **Security Focused:**
    *   Written in Rust for memory safety.
    *   Secure handling of file operations and external processes.
    *   Uses robust libraries for parsing, hashing, and string matching.
    *   Avoids shell interpretation risks where possible (except for `lsof`).
*   **Performance:** Leverages Rust's performance and multi-threading (via Rayon) for faster filesystem scanning.
*   **Configuration:** Configurable via environment variables (see `src/config.rs` for details and defaults).
*   **Logging:** Flexible logging to console, file (with daily rotation), and optionally syslog (requires feature flag).
*   **Dependency Bundling:** Aims to produce statically linked binaries (especially on Linux with MUSL) for easier deployment with minimal runtime dependencies (except `lsof` if C2 check is enabled).

## Why Fenrir Rust?

This rewrite addresses limitations of the original Bash script:

1.  **Security:** Reduces reliance on numerous external shell commands, minimizing potential command injection surfaces. Leverages Rust's memory safety guarantees.
2.  **Portability:** Provides pre-compiled binaries for Linux (x86_64, aarch64 - GNU & MUSL), macOS (x86_64, aarch64), and Windows (x86_64, aarch64) via GitHub Actions.
3.  **Performance:** Uses optimized Rust libraries and parallelism for potentially faster scans.
4.  **Maintainability:** Offers a more structured codebase compared to a large Bash script.

**Trade-off:** The C2 check currently still relies on the external `lsof` command for direct feature parity. A pure-Rust implementation of `lsof`'s network connection inspection is significantly more complex and platform-dependent.

## Usage

### Pre-compiled Binaries

Download the appropriate binary for your OS and architecture from the [GitHub Releases](https://github.com/<your-username>/<your-repo-name>/releases) page. Place the binary alongside the IOC definition files:

*   `hash-iocs.txt`
*   `string-iocs.txt`
*   `filename-iocs.txt`
*   `c2-iocs.txt`

Make the binary executable (on Linux/macOS): `chmod +x fenrir-rust-<target>`

Run the scan:

```bash
./fenrir-rust-<target> /path/to/scan
```

**Example:** Scan the root directory on Linux MUSL:

```bash
./fenrir-rust-x86_64-linux-musl /
```

## Configuration

Configure Fenrir Rust primarily through **environment variables**. See `src/config.rs` for all available variables and their defaults.

**Key Environment Variables:**

*   `FENRIR_DEBUG=1`: Enable debug logging.
*   `FENRIR_HASH_IOC_FILE=./path/to/hashes.txt`: Override hash IOC file path.
*   `FENRIR_DISABLE_C2_CHECK=1`: Disable the `lsof`-based C2 check.
*   `FENRIR_MAX_FILE_SIZE_KB=10000`: Set max file size (KB) for hash/string checks.
*   `FENRIR_MIN_HOT_EPOCH=1678886400`: Set min Unix timestamp for timeframe check.
*   `FENRIR_MAX_HOT_EPOCH=1678972800`: Set max Unix timestamp for timeframe check.
*   `FENRIR_ENABLE_TIMEFRAME_CHECK=1`: Enable the timeframe check.
*   `FENRIR_LOG_TO_SYSLOG=1`: Enable syslog logging (if feature compiled).
*   `FENRIR_LOG_FILE_PATTERN="./logs/scan_{HOSTNAME}_{DATE}.log"`: Customize log file path/name.
*   `FENRIR_NUM_THREADS=4`: Set the number of threads for file scanning.

**Command-line overrides:** Some common options can also be set via command-line flags (e.g., `--debug`, `--hash-iocs FILE`, `--threads N`). Run `./fenrir-rust-<target> --help` for details.

### Building from Source

1.  **Install Rust:** Follow the instructions at [rustup.rs](https://rustup.rs/).
2.  **Clone the repository:** `git clone https://github.com/<your-username>/<your-repo-name>.git`
3.  **Navigate to the directory:** `cd fenrir-rust`
4.  **Build:**
    *   Debug build: `cargo build`
    *   Release build (optimized): `cargo build --release`
    *   Build for a specific target (e.g., static Linux): `rustup target add x86_64-unknown-linux-musl && cargo build --target x86_64-unknown-linux-musl --release`
5.  The executable will be in `target/debug/` or `target/release/` (or `target/<target>/release/`).

**Optional Syslog Feature:**
To include syslog support, build with the feature flag:
`cargo build --release --features syslog_logging`

## Dependencies

*   **Runtime:**
    *   `lsof`: Required *only* if the C2 check (`FENRIR_ENABLE_C2_CHECK=1`, default) is enabled. Must be in the system's PATH.
*   **Buildtime:**
    *   Rust toolchain (Cargo, rustc)
    *   Standard C build tools (make, gcc - often needed for Rust build scripts or dependencies)
    *   Cross-compilation linkers (e.g., `gcc-aarch64-linux-gnu`) if cross-compiling on Linux.
    *   Docker (if using the `cross` crate for easier cross-compilation).

## Security Considerations

*   **`lsof` Execution:** The C2 check executes the external `lsof` command. While arguments are passed carefully without shell interpretation (`shell=false`), relying on external binaries always carries some inherent risk. Ensure `lsof` is a trusted version. Disable the C2 check (`FENRIR_DISABLE_C2_CHECK=1`) if this risk is unacceptable.
*   **Input Validation:** IOC files and configuration are parsed defensively, but malformed IOCs could potentially lead to unexpected behavior (though less likely to cause security vulnerabilities compared to command injection).
*   **File Access:** The scanner requires read access to the files and directories it scans. Run with appropriate permissions. Avoid running as root unless necessary to scan protected system files, understanding the inherent risks.
*   **Dependencies:** Rust dependencies are vetted via `cargo audit` (or similar tools) in CI where possible, but reviewing dependencies is crucial.

## License

This rewrite is licensed under the [MIT](LICENSE) license. The original Fenrir script has its own licensing terms.

## Contributing

Contributions (bug reports, feature requests, pull requests) are welcome! Please adhere to security best practices.
