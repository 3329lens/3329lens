/*
 * Cryptographic Library Scanner Module - Defensive Security
 *
 * This module provides comprehensive scanning capabilities for identifying cryptographic
 * libraries, functions, and dependencies within local file systems.
 *
 * Key Features:
 * - Filename-based detection of crypto libraries (libssl, libcrypto, etc.)
 * - Dependency manifest parsing (Cargo.toml, package.json, requirements.txt,
 *   pyproject.toml, Pipfile)
 * - Source code scanning for crypto API usage
 * - Comprehensive reporting with categorization
 *
 * Purpose: Defensive security tool for cryptographic inventory and post-quantum migration planning
 * Part of the Slow Lynx Cryptography Discovery project
 */

use walkdir::WalkDir;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

/// Maximum file size for manifest files (10 MB)
/// Prevents DoS attacks via maliciously large Cargo.toml, package.json, etc.
/// Shared with the lockfile parser, which reuses the same guard.
pub(crate) const MAX_MANIFEST_SIZE: u64 = 10 * 1024 * 1024;

/// Canonicalize and validate a scan path to prevent directory traversal.
///
/// This provides defense-in-depth at the scanner level, complementing
/// path validation at the CLI layer. Resolves:
/// - Relative paths to absolute
/// - Parent references (../)
/// - Symlinks
///
/// Returns the canonicalized path or an error if invalid.
fn canonicalize_path(path: &str) -> Result<PathBuf, std::io::Error> {
    let canonical = fs::canonicalize(path)?;

    // Ensure it's a directory for scanning
    if !canonical.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Path is not a directory: {}", canonical.display()),
        ));
    }

    Ok(canonical)
}

/// Error type for file size limit exceeded
#[derive(Debug)]
pub struct FileTooLargeError {
    pub path: PathBuf,
    pub size: u64,
    pub limit: u64,
}

impl std::fmt::Display for FileTooLargeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "File too large: {} ({} bytes exceeds {} byte limit)",
            self.path.display(),
            self.size,
            self.limit
        )
    }
}

impl std::error::Error for FileTooLargeError {}

/// Safely read a file with size limit to prevent DoS
/// Returns Ok(content) if file is within size limit, Err otherwise
pub(crate) fn read_file_with_limit(path: &Path, max_size: u64) -> Result<String, std::io::Error> {
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();

    if file_size > max_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            FileTooLargeError {
                path: path.to_path_buf(),
                size: file_size,
                limit: max_size,
            },
        ));
    }

    // File is within limits, read it
    let mut file = File::open(path)?;
    let mut content = String::with_capacity(file_size as usize);
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// Extract a version string from a Cargo dependency value.
/// Handles both `crate = "1.2.3"` and `crate = { version = "1.2.3", ... }`.
fn extract_toml_version(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(s) => clean_version_req(s),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .and_then(clean_version_req),
        _ => None,
    }
}

/// Normalize a declared version requirement into a plain version usable in a purl.
/// Strips common range operators (^, ~, >=, etc.); returns None if nothing remains.
fn clean_version_req(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_start_matches(|c| matches!(c, '^' | '~' | '=' | '>' | '<' | ' '))
        .trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Source ecosystem a finding originated from (drives purl construction).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Cargo,   // Rust crate (Cargo.toml)
    Npm,     // Node.js package (package.json)
    PyPI,    // Python package (requirements.txt)
    System,  // Binary/static library on disk (no package coordinate)
}

/// Provenance of a finding's version string.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum VersionSource {
    /// Version comes from a manifest requirement (declared, not resolved).
    /// Also used when no version is known (e.g. binary libraries on disk).
    Declared,
    /// Version resolved from a lockfile — the actual deployed version.
    /// Only `Locked` versions are eligible for advisory correlation.
    Locked,
}

/// Represents a detected cryptographic library or dependency
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CryptoFinding {
    pub path: String,
    /// Crate/package name for manifests; filename for binary libraries.
    pub name: String,
    pub finding_type: FindingType,
    pub crypto_type: CryptoType,
    pub ecosystem: Ecosystem,
    /// Version string: lockfile-resolved when `version_source == Locked`,
    /// otherwise the declared manifest requirement (if any).
    pub version: Option<String>,
    /// Where `version` came from (declared requirement vs. lockfile-resolved).
    pub version_source: VersionSource,
    pub details: String,
}

/// Type of finding (how it was detected)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum FindingType {
    BinaryLibrary,         // Shared library file (.so, .dll, .dylib)
    StaticLibrary,         // Static library (.a)
    DependencyManifest,    // Found directly in Cargo.toml, package.json, etc.
    TransitiveDependency,  // Resolved from a lockfile but not declared directly
    SourceCode,            // Found in source code
}

/// Crypto crates of interest in Cargo manifests/lockfiles, with their category.
/// Single source of truth shared by the manifest and lockfile code paths.
fn cargo_crypto_crates() -> Vec<(&'static str, CryptoType)> {
    vec![
        ("ring", CryptoType::GeneralCrypto),
        ("rustls", CryptoType::SslTls),
        ("openssl", CryptoType::SslTls),
        ("sodiumoxide", CryptoType::GeneralCrypto),
        ("chacha20", CryptoType::GeneralCrypto),
        ("aes", CryptoType::GeneralCrypto),
        ("sha2", CryptoType::HashFunction),
        ("sha3", CryptoType::HashFunction),
        ("blake2", CryptoType::HashFunction),
        ("blake3", CryptoType::HashFunction),
        ("argon2", CryptoType::GeneralCrypto),
        ("ed25519", CryptoType::GeneralCrypto),
        ("x25519", CryptoType::GeneralCrypto),
        ("rsa", CryptoType::GeneralCrypto),
        ("pqcrypto", CryptoType::PostQuantum),
        ("oqs", CryptoType::PostQuantum),
    ]
}

/// Crypto packages of interest in npm manifests/lockfiles, with their category.
/// Single source of truth shared by the manifest and lockfile code paths.
///
/// Names are matched exactly, so generic-looking entries (`jose`, `pem`, `md5`)
/// are safe — they are real package names, not substrings.
///
/// Every entry was checked to exist on the registry and to be genuinely
/// cryptographic rather than merely crypto-adjacent; a proxy agent or a
/// base64 codec does not belong here. The JOSE/JWT and browserify-shim families
/// dominate real dependency trees: a bare `jsonwebtoken` install pulls in `jwa`,
/// `jws`, `ecdsa-sig-formatter` and `buffer-equal-constant-time`, none of which
/// the original six-entry table saw.
#[cfg(test)]
pub(crate) fn npm_crypto_packages_for_test() -> Vec<(&'static str, CryptoType)> {
    npm_crypto_packages()
}

fn npm_crypto_packages() -> Vec<(&'static str, CryptoType)> {
    vec![
        // Umbrella / general-purpose crypto libraries.
        ("crypto", CryptoType::GeneralCrypto),
        ("crypto-js", CryptoType::GeneralCrypto),
        ("crypto-browserify", CryptoType::GeneralCrypto),
        ("node-forge", CryptoType::GeneralCrypto),
        ("jsrsasign", CryptoType::GeneralCrypto),
        ("openpgp", CryptoType::GeneralCrypto),
        // NaCl / libsodium family.
        ("tweetnacl", CryptoType::GeneralCrypto),
        ("tweetnacl-util", CryptoType::GeneralCrypto),
        ("libsodium", CryptoType::GeneralCrypto),
        ("libsodium-wrappers", CryptoType::GeneralCrypto),
        ("sodium-native", CryptoType::GeneralCrypto),
        ("@stablelib/chacha20poly1305", CryptoType::GeneralCrypto),
        // JOSE / JWT — signing and encryption, overwhelmingly RSA and ECDSA.
        ("jose", CryptoType::GeneralCrypto),
        ("node-jose", CryptoType::GeneralCrypto),
        ("jsonwebtoken", CryptoType::GeneralCrypto),
        ("jws", CryptoType::GeneralCrypto),
        ("jwa", CryptoType::GeneralCrypto),
        ("ecdsa-sig-formatter", CryptoType::GeneralCrypto),
        // Asymmetric primitives — all Shor-breakable, so they matter most to
        // the post-quantum risk assessment.
        ("elliptic", CryptoType::GeneralCrypto),
        ("secp256k1", CryptoType::GeneralCrypto),
        ("eccrypto", CryptoType::GeneralCrypto),
        ("node-rsa", CryptoType::GeneralCrypto),
        ("public-encrypt", CryptoType::GeneralCrypto),
        ("browserify-sign", CryptoType::GeneralCrypto),
        ("diffie-hellman", CryptoType::GeneralCrypto),
        ("@noble/curves", CryptoType::GeneralCrypto),
        ("@noble/secp256k1", CryptoType::GeneralCrypto),
        // Symmetric ciphers.
        ("aes-js", CryptoType::GeneralCrypto),
        ("browserify-aes", CryptoType::GeneralCrypto),
        ("@noble/ciphers", CryptoType::GeneralCrypto),
        // Password hashing and key derivation.
        ("bcrypt", CryptoType::GeneralCrypto),
        ("bcryptjs", CryptoType::GeneralCrypto),
        ("argon2", CryptoType::GeneralCrypto),
        ("scrypt-js", CryptoType::GeneralCrypto),
        ("pbkdf2", CryptoType::GeneralCrypto),
        // MACs and randomness.
        ("create-hmac", CryptoType::GeneralCrypto),
        ("randombytes", CryptoType::GeneralCrypto),
        ("buffer-equal-constant-time", CryptoType::GeneralCrypto),
        // Dedicated hash implementations.
        ("@noble/hashes", CryptoType::HashFunction),
        ("hash.js", CryptoType::HashFunction),
        ("sha.js", CryptoType::HashFunction),
        ("create-hash", CryptoType::HashFunction),
        ("js-sha256", CryptoType::HashFunction),
        ("js-sha3", CryptoType::HashFunction),
        ("keccak", CryptoType::HashFunction),
        ("blakejs", CryptoType::HashFunction),
        ("md5", CryptoType::HashFunction),
        // X.509 / TLS certificate tooling.
        ("selfsigned", CryptoType::SslTls),
        ("pem", CryptoType::SslTls),
        // Post-quantum.
        ("@noble/post-quantum", CryptoType::PostQuantum),
    ]
}

/// Crypto packages of interest in PyPI manifests/lockfiles, keyed by their
/// PEP 503-normalized name (so the table, lockfile keys, parsed manifest names,
/// and OSV advisory names all compare equal). Single source of truth.
fn pypi_crypto_packages() -> Vec<(&'static str, CryptoType)> {
    vec![
        ("cryptography", CryptoType::GeneralCrypto),
        ("pycryptodome", CryptoType::GeneralCrypto),
        ("pyopenssl", CryptoType::SslTls),
        ("pynacl", CryptoType::GeneralCrypto),
        ("bcrypt", CryptoType::GeneralCrypto),
    ]
}

/// Normalize a PyPI project name per PEP 503: lowercase and collapse any run of
/// `-`, `_`, or `.` into a single `-`. E.g. `PyOpenSSL` -> `pyopenssl`,
/// `ruamel.yaml` -> `ruamel-yaml`. This is the canonical form used for all
/// PyPI name comparisons (findings, lockfile keys, OSV advisory names).
pub fn normalize_pypi_name(name: &str) -> String {
    // Exactly PEP 503's `re.sub(r"[-_.]+", "-", name).lower()`: collapse each run
    // of separators to a single `-`, then lowercase. Leading and trailing
    // separators are preserved, not stripped — PEP 508 forbids names shaped that
    // way, but advisory feeds do carry them (the OSV malware feed has entries
    // like `urlcon-`), and silently normalizing them differently from the
    // published formula makes our keys disagree with everyone else's.
    let lower = name.trim().to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_sep = false;
    for c in lower.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c);
            prev_sep = false;
        }
    }
    out
}

/// Match a normalized PyPI name against the crypto table (exact equality).
fn match_pypi_crypto(normalized: &str) -> Option<CryptoType> {
    pypi_crypto_packages()
        .into_iter()
        .find(|(canon, _)| normalized == *canon)
        .map(|(_, t)| t)
}

/// Build PyPI findings from a `requirements.txt` body. A `==` pin is treated as
/// resolved (`Locked`) — an exact pin is the deployed version; ranges and
/// unpinned entries are `Declared`. Shared by the batch and streaming paths.
fn pypi_findings_from_requirements(content: &str, path: &Path) -> Vec<CryptoFinding> {
    let mut out = Vec::new();
    for raw in content.lines() {
        // Drop inline comments and pip option lines (`-r`, `--hash`, `-e`, …).
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        // Project name = leading run of PEP 508 name characters.
        let name_end = line
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
            .unwrap_or(line.len());
        let raw_name = &line[..name_end];
        if raw_name.is_empty() {
            continue;
        }
        let normalized = normalize_pypi_name(raw_name);
        let crypto_type = match match_pypi_crypto(&normalized) {
            Some(t) => t,
            None => continue,
        };
        let spec = line[name_end..].trim();
        let (version, version_source) = if let Some(rest) = spec.strip_prefix("==") {
            // Exact pin: take the version token, stopping at any marker/extra.
            let ver = rest
                .trim()
                .split(|c: char| matches!(c, ' ' | ';' | ','))
                .next()
                .unwrap_or("")
                .trim();
            if ver.is_empty() {
                (None, VersionSource::Declared)
            } else {
                (Some(ver.to_string()), VersionSource::Locked)
            }
        } else {
            (clean_version_req(spec), VersionSource::Declared)
        };
        out.push(CryptoFinding {
            path: path.display().to_string(),
            name: normalized.clone(),
            finding_type: FindingType::DependencyManifest,
            crypto_type,
            ecosystem: Ecosystem::PyPI,
            version,
            version_source,
            details: format!("Python package dependency: {}", normalized),
        });
    }
    out
}

/// Build PyPI findings for a manifest (pyproject.toml / Pipfile) from its
/// declared-name set and an optional resolved lock map. Mirrors the Cargo/npm
/// declared-vs-transitive split. Shared by the batch and streaming paths.
fn pypi_findings_from_manifest(
    path: &Path,
    declared: &std::collections::HashSet<String>,
    lock: Option<&HashMap<String, String>>,
) -> Vec<CryptoFinding> {
    let mut out = Vec::new();
    for (canon, crypto_type) in pypi_crypto_packages() {
        let locked = lock.and_then(|l| l.get(canon)).cloned();
        if declared.contains(canon) {
            let (version, version_source) = resolve_version(None, locked);
            out.push(CryptoFinding {
                path: path.display().to_string(),
                name: canon.to_string(),
                finding_type: FindingType::DependencyManifest,
                crypto_type,
                ecosystem: Ecosystem::PyPI,
                version,
                version_source,
                details: format!("Python package dependency: {}", canon),
            });
        } else if let Some(version) = locked {
            out.push(CryptoFinding {
                path: path.display().to_string(),
                name: canon.to_string(),
                finding_type: FindingType::TransitiveDependency,
                crypto_type,
                ecosystem: Ecosystem::PyPI,
                version: Some(version),
                version_source: VersionSource::Locked,
                details: format!("Transitive Python package (from lockfile): {}", canon),
            });
        }
    }
    out
}

/// Leading project-name token of a PEP 508 requirement string (`"cryptography>=41"`
/// -> `"cryptography"`). Returns `None` for an empty/invalid leading token.
fn pep508_name(req: &str) -> Option<&str> {
    let req = req.trim();
    let end = req
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(req.len());
    if end == 0 {
        None
    } else {
        Some(&req[..end])
    }
}

/// Extract declared crypto package names (normalized) from a `pyproject.toml`.
/// Covers Poetry (`[tool.poetry.dependencies]` and group deps) and PEP 621
/// (`[project] dependencies` / `optional-dependencies`).
fn pyproject_declared_names(parsed: &toml::Value) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();

    let poetry = parsed.get("tool").and_then(|t| t.get("poetry"));
    if let Some(t) = poetry.and_then(|p| p.get("dependencies")).and_then(|d| d.as_table()) {
        for k in t.keys() {
            names.insert(normalize_pypi_name(k));
        }
    }
    // Poetry group deps: [tool.poetry.group.<g>.dependencies]
    if let Some(groups) = poetry.and_then(|p| p.get("group")).and_then(|g| g.as_table()) {
        for group in groups.values() {
            if let Some(deps) = group.get("dependencies").and_then(|d| d.as_table()) {
                for k in deps.keys() {
                    names.insert(normalize_pypi_name(k));
                }
            }
        }
    }
    // PEP 621: [project] dependencies + optional-dependencies (PEP 508 strings).
    if let Some(project) = parsed.get("project") {
        let mut arrays: Vec<&toml::Value> = Vec::new();
        if let Some(d) = project.get("dependencies") {
            arrays.push(d);
        }
        if let Some(opt) = project.get("optional-dependencies").and_then(|o| o.as_table()) {
            arrays.extend(opt.values());
        }
        for arr in arrays {
            if let Some(items) = arr.as_array() {
                for item in items {
                    if let Some(name) = item.as_str().and_then(pep508_name) {
                        names.insert(normalize_pypi_name(name));
                    }
                }
            }
        }
    }
    names
}

/// Extract declared package names (normalized) from a `Pipfile` (`[packages]`
/// and `[dev-packages]` table keys).
fn pipfile_declared_names(parsed: &toml::Value) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for section in ["packages", "dev-packages"] {
        if let Some(t) = parsed.get(section).and_then(|v| v.as_table()) {
            for k in t.keys() {
                names.insert(normalize_pypi_name(k));
            }
        }
    }
    names
}

/// Decide a finding's version + provenance: prefer the lockfile-resolved version
/// (`Locked`) over the declared manifest requirement (`Declared`).
fn resolve_version(
    declared: Option<String>,
    locked: Option<String>,
) -> (Option<String>, VersionSource) {
    match locked {
        Some(v) => (Some(v), VersionSource::Locked),
        None => (declared, VersionSource::Declared),
    }
}

/// Category of cryptographic implementation
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum CryptoType {
    SslTls,            // OpenSSL, LibreSSL, BoringSSL
    GeneralCrypto,     // Crypto++, libsodium, Bouncy Castle
    PostQuantum,       // liboqs, Kyber, Dilithium implementations
    HashFunction,      // Dedicated hash libraries
    Unknown,           // Detected but not categorized
}

/// Main scanner structure
pub struct CryptoScanner {
    findings: Vec<CryptoFinding>,
    library_patterns: HashMap<String, CryptoType>,
}

impl CryptoScanner {
    pub fn new() -> Self {
        let mut library_patterns = HashMap::new();

        // SSL/TLS libraries
        library_patterns.insert("libssl".to_string(), CryptoType::SslTls);
        library_patterns.insert("libcrypto".to_string(), CryptoType::SslTls);
        library_patterns.insert("openssl".to_string(), CryptoType::SslTls);
        library_patterns.insert("libressl".to_string(), CryptoType::SslTls);
        library_patterns.insert("boringssl".to_string(), CryptoType::SslTls);
        library_patterns.insert("mbedtls".to_string(), CryptoType::SslTls);
        library_patterns.insert("wolfssl".to_string(), CryptoType::SslTls);

        // General crypto libraries
        library_patterns.insert("libsodium".to_string(), CryptoType::GeneralCrypto);
        library_patterns.insert("nacl".to_string(), CryptoType::GeneralCrypto);
        library_patterns.insert("bcrypt".to_string(), CryptoType::GeneralCrypto);
        library_patterns.insert("cryptopp".to_string(), CryptoType::GeneralCrypto);
        library_patterns.insert("bouncycastle".to_string(), CryptoType::GeneralCrypto);
        library_patterns.insert("libgcrypt".to_string(), CryptoType::GeneralCrypto);

        // Post-quantum libraries
        library_patterns.insert("liboqs".to_string(), CryptoType::PostQuantum);
        library_patterns.insert("kyber".to_string(), CryptoType::PostQuantum);
        library_patterns.insert("dilithium".to_string(), CryptoType::PostQuantum);
        library_patterns.insert("falcon".to_string(), CryptoType::PostQuantum);
        library_patterns.insert("sphincs".to_string(), CryptoType::PostQuantum);

        Self {
            findings: Vec::new(),
            library_patterns,
        }
    }

    /// Main scanning entry point
    pub fn scan(&mut self, root_path: &str, max_depth: Option<usize>) -> Result<(), std::io::Error> {
        // Canonicalize path to prevent directory traversal attacks
        // Defense-in-depth: validates even if CLI layer already canonicalized
        let canonical_path = canonicalize_path(root_path)?;
        let path_str = canonical_path.to_string_lossy();

        println!("Starting crypto library scan at: {}", path_str);

        // Scan for binary libraries
        self.scan_libraries(&path_str, max_depth)?;

        // Scan for dependency manifests
        self.scan_manifests(&path_str, max_depth)?;

        Ok(())
    }

    /// Scan for binary library files
    fn scan_libraries(&mut self, root_path: &str, max_depth: Option<usize>) -> Result<(), std::io::Error> {
        // Disable symlink following to prevent:
        // 1. Symlink loop DoS (circular symlinks causing infinite traversal)
        // 2. Escaping scan boundaries via symlinks to sensitive directories
        let mut walker = WalkDir::new(root_path).follow_links(false);

        if let Some(depth) = max_depth {
            walker = walker.max_depth(depth);
        }

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            // Skip if not a file
            if !path.is_file() {
                continue;
            }

            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Check for library extensions
            if self.is_library_file(filename) {
                if let Some((crypto_name, crypto_type)) = self.identify_crypto_library(filename) {
                    self.findings.push(CryptoFinding {
                        path: path.display().to_string(),
                        name: filename.to_string(),
                        finding_type: if filename.ends_with(".a") {
                            FindingType::StaticLibrary
                        } else {
                            FindingType::BinaryLibrary
                        },
                        crypto_type,
                        ecosystem: Ecosystem::System,
                        version: None,
                        version_source: VersionSource::Declared,
                        details: format!("Detected: {}", crypto_name),
                    });
                }
            }
        }

        Ok(())
    }

    /// Scan for dependency manifests (Cargo.toml, package.json, etc.)
    fn scan_manifests(&mut self, root_path: &str, max_depth: Option<usize>) -> Result<(), std::io::Error> {
        // Disable symlink following to prevent symlink loops and boundary escapes
        let mut walker = WalkDir::new(root_path).follow_links(false);

        if let Some(depth) = max_depth {
            walker = walker.max_depth(depth);
        }

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            match filename {
                "Cargo.toml" => self.scan_cargo_toml(path)?,
                "package.json" => self.scan_package_json(path)?,
                "requirements.txt" => self.scan_requirements_txt(path)?,
                "pyproject.toml" => self.scan_pyproject_toml(path)?,
                "Pipfile" => self.scan_pipfile(path)?,
                _ => {}
            }
        }

        Ok(())
    }

    /// Parse Cargo.toml for Rust crypto dependencies
    fn scan_cargo_toml(&mut self, path: &Path) -> Result<(), std::io::Error> {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // File too large, skip silently (could log in verbose mode)
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let parsed = match toml::from_str::<toml::Value>(&content) {
            Ok(p) => p,
            Err(_) => return Ok(()), // Skip malformed TOML files
        };

        let crypto_crates = cargo_crypto_crates();
        // Resolved versions from a sibling Cargo.lock, when present.
        let lock = crate::lockfile::resolve_from_sibling_lock(path);

        // Crypto crates declared directly in this manifest (so we don't also
        // report them as transitive).
        let mut declared: std::collections::HashSet<&str> = std::collections::HashSet::new();

        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_table()) {
            for (crate_name, crypto_type) in &crypto_crates {
                if let Some(dep_value) = deps.get(*crate_name) {
                    declared.insert(*crate_name);
                    let (version, version_source) = resolve_version(
                        extract_toml_version(dep_value),
                        lock.as_ref().and_then(|l| l.get(*crate_name).cloned()),
                    );
                    self.findings.push(CryptoFinding {
                        path: path.display().to_string(),
                        name: crate_name.to_string(),
                        finding_type: FindingType::DependencyManifest,
                        crypto_type: crypto_type.clone(),
                        ecosystem: Ecosystem::Cargo,
                        version,
                        version_source,
                        details: format!("Rust crate dependency: {}", crate_name),
                    });
                }
            }
        }

        // Transitive crypto: crates present in the lockfile but not declared
        // directly in this manifest. This is where most crypto actually lives.
        if let Some(lock) = lock.as_ref() {
            for (crate_name, crypto_type) in &crypto_crates {
                if declared.contains(*crate_name) {
                    continue;
                }
                if let Some(version) = lock.get(*crate_name) {
                    self.findings.push(CryptoFinding {
                        path: path.display().to_string(),
                        name: crate_name.to_string(),
                        finding_type: FindingType::TransitiveDependency,
                        crypto_type: crypto_type.clone(),
                        ecosystem: Ecosystem::Cargo,
                        version: Some(version.clone()),
                        version_source: VersionSource::Locked,
                        details: format!("Transitive Rust crate (from Cargo.lock): {}", crate_name),
                    });
                }
            }
        }

        Ok(())
    }

    /// Parse package.json for Node.js crypto dependencies
    fn scan_package_json(&mut self, path: &Path) -> Result<(), std::io::Error> {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // File too large, skip silently
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(parsed) => {
                let crypto_packages = npm_crypto_packages();
                // Resolved versions from a sibling npm lockfile, when present.
                let lock = crate::lockfile::resolve_npm_from_sibling_lock(path);

                // Crypto packages declared directly here (so we don't also report
                // them as transitive).
                let mut declared: std::collections::HashSet<&str> = std::collections::HashSet::new();

                if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
                    for (pkg_name, crypto_type) in &crypto_packages {
                        if let Some(ver_value) = deps.get(*pkg_name) {
                            declared.insert(*pkg_name);
                            let (version, version_source) = resolve_version(
                                ver_value.as_str().and_then(clean_version_req),
                                lock.as_ref().and_then(|l| l.get(*pkg_name).cloned()),
                            );
                            self.findings.push(CryptoFinding {
                                path: path.display().to_string(),
                                name: pkg_name.to_string(),
                                finding_type: FindingType::DependencyManifest,
                                crypto_type: crypto_type.clone(),
                                ecosystem: Ecosystem::Npm,
                                version,
                                version_source,
                                details: format!("Node.js package dependency: {}", pkg_name),
                            });
                        }
                    }
                }

                // Transitive crypto: packages in the lockfile but not declared
                // directly in this manifest.
                if let Some(lock) = lock.as_ref() {
                    for (pkg_name, crypto_type) in &crypto_packages {
                        if declared.contains(*pkg_name) {
                            continue;
                        }
                        if let Some(version) = lock.get(*pkg_name) {
                            self.findings.push(CryptoFinding {
                                path: path.display().to_string(),
                                name: pkg_name.to_string(),
                                finding_type: FindingType::TransitiveDependency,
                                crypto_type: crypto_type.clone(),
                                ecosystem: Ecosystem::Npm,
                                version: Some(version.clone()),
                                version_source: VersionSource::Locked,
                                details: format!("Transitive Node.js package (from package-lock.json): {}", pkg_name),
                            });
                        }
                    }
                }
            }
            Err(_) => {
                // Skip malformed JSON files
            }
        }

        Ok(())
    }

    /// Parse requirements.txt for Python crypto dependencies
    fn scan_requirements_txt(&mut self, path: &Path) -> Result<(), std::io::Error> {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // File too large, skip silently
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        for finding in pypi_findings_from_requirements(&content, path) {
            self.findings.push(finding);
        }

        Ok(())
    }

    /// Parse pyproject.toml (Poetry / PEP 621) for Python crypto dependencies,
    /// resolving versions from a sibling poetry.lock when present.
    fn scan_pyproject_toml(&mut self, path: &Path) -> Result<(), std::io::Error> {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Ok(()),
            Err(e) => return Err(e),
        };
        let parsed = match toml::from_str::<toml::Value>(&content) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let declared = pyproject_declared_names(&parsed);
        let lock = crate::lockfile::resolve_pypi_from_sibling_lock(path);
        for finding in pypi_findings_from_manifest(path, &declared, lock.as_ref()) {
            self.findings.push(finding);
        }
        Ok(())
    }

    /// Parse a Pipfile (pipenv) for Python crypto dependencies, resolving
    /// versions from a sibling Pipfile.lock when present.
    fn scan_pipfile(&mut self, path: &Path) -> Result<(), std::io::Error> {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Ok(()),
            Err(e) => return Err(e),
        };
        let parsed = match toml::from_str::<toml::Value>(&content) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let declared = pipfile_declared_names(&parsed);
        let lock = crate::lockfile::resolve_pypi_from_sibling_lock(path);
        for finding in pypi_findings_from_manifest(path, &declared, lock.as_ref()) {
            self.findings.push(finding);
        }
        Ok(())
    }

    /// Check if filename matches library file patterns
    fn is_library_file(&self, filename: &str) -> bool {
        let extensions = [".so", ".dll", ".dylib", ".a"];
        extensions.iter().any(|ext| filename.contains(ext))
    }

    /// Identify crypto library from filename
    fn identify_crypto_library(&self, filename: &str) -> Option<(String, CryptoType)> {
        let lower_name = filename.to_lowercase();

        for (pattern, crypto_type) in &self.library_patterns {
            if lower_name.contains(pattern) {
                return Some((pattern.clone(), crypto_type.clone()));
            }
        }

        None
    }

    /// Get scan results
    pub fn get_findings(&self) -> &Vec<CryptoFinding> {
        &self.findings
    }

    /// Get findings count by type
    pub fn get_statistics(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();

        stats.insert("total".to_string(), self.findings.len());

        let mut by_type: HashMap<FindingType, usize> = HashMap::new();
        let mut by_crypto: HashMap<CryptoType, usize> = HashMap::new();

        for finding in &self.findings {
            *by_type.entry(finding.finding_type.clone()).or_insert(0) += 1;
            *by_crypto.entry(finding.crypto_type.clone()).or_insert(0) += 1;
        }

        stats.insert("binary_libraries".to_string(), *by_type.get(&FindingType::BinaryLibrary).unwrap_or(&0));
        stats.insert("static_libraries".to_string(), *by_type.get(&FindingType::StaticLibrary).unwrap_or(&0));
        stats.insert("manifests".to_string(), *by_type.get(&FindingType::DependencyManifest).unwrap_or(&0));
        stats.insert("transitive".to_string(), *by_type.get(&FindingType::TransitiveDependency).unwrap_or(&0));
        stats.insert("ssl_tls".to_string(), *by_crypto.get(&CryptoType::SslTls).unwrap_or(&0));
        stats.insert("general_crypto".to_string(), *by_crypto.get(&CryptoType::GeneralCrypto).unwrap_or(&0));
        stats.insert("post_quantum".to_string(), *by_crypto.get(&CryptoType::PostQuantum).unwrap_or(&0));

        stats
    }

    /// Convert CryptoFinding to LibraryInfo for the dashboard
    fn finding_to_library_info(&self, finding: &CryptoFinding) -> crate::library::LibraryInfo {
        use crate::library::{LibraryInfo, LibraryCategory, LibraryType};

        let path = PathBuf::from(&finding.path);

        // Name is captured at detection time (crate/package name for manifests,
        // filename for binary libraries).
        let name = finding.name.clone();

        // Convert CryptoType to LibraryCategory
        let category = match finding.crypto_type {
            CryptoType::SslTls => LibraryCategory::SslTls,
            CryptoType::GeneralCrypto => LibraryCategory::GeneralCrypto,
            CryptoType::PostQuantum => LibraryCategory::PostQuantum,
            CryptoType::HashFunction => LibraryCategory::HashFunction,
            CryptoType::Unknown => LibraryCategory::Other,
        };

        // Convert FindingType to LibraryType
        let library_type = match finding.finding_type {
            FindingType::BinaryLibrary => LibraryType::SharedLibrary,
            FindingType::StaticLibrary => LibraryType::StaticLibrary,
            FindingType::DependencyManifest => LibraryType::Manifest,
            FindingType::TransitiveDependency => LibraryType::Manifest, // Resolved from lockfile
            FindingType::SourceCode => LibraryType::Manifest, // Treat as manifest for now
        };

        // Assess risk based on category and library name
        let (risk_level, quantum_vulnerable) = self.assess_risk(&name, &category);

        // Get file metadata
        let (size, modified) = fs::metadata(&path)
            .map(|m| (m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)))
            .unwrap_or((0, SystemTime::UNIX_EPOCH));

        // Version captured at detection time (declared manifest requirement).
        let version = finding.version.clone();

        LibraryInfo {
            name,
            path,
            category,
            library_type,
            version,
            vendor: None, // TODO: Could extract from name
            size,
            modified,
            risk_level,
            quantum_vulnerable,
        }
    }

    /// Assess quantum risk based on library name and category
    fn assess_risk(&self, name: &str, category: &crate::library::LibraryCategory) -> (crate::library::RiskLevel, bool) {
        use crate::library::{LibraryCategory, RiskLevel};

        let lower_name = name.to_lowercase();

        // Post-quantum libraries have no risk
        if matches!(category, LibraryCategory::PostQuantum) {
            return (RiskLevel::None, false);
        }

        // Hash-only libraries have low risk
        if matches!(category, LibraryCategory::HashFunction) {
            return (RiskLevel::Low, false);
        }

        // Check for known vulnerable algorithms
        if lower_name.contains("rsa") || lower_name.contains("dsa") {
            return (RiskLevel::High, true);
        }

        // ECC is medium risk (longer quantum resistance than RSA)
        if lower_name.contains("ecc") || lower_name.contains("ecdsa") || lower_name.contains("ecdh") {
            return (RiskLevel::Medium, true);
        }

        // Modern libraries like libsodium, rustls are generally better
        if lower_name.contains("sodium") || lower_name.contains("rustls") {
            return (RiskLevel::Low, false);
        }

        // Default: medium risk for general crypto
        (RiskLevel::Medium, true)
    }

    /// Streaming scan with progress callbacks
    pub fn scan_streaming<F>(
        &mut self,
        root_path: &str,
        max_depth: Option<usize>,
        mut callback: F,
    ) -> Result<(), std::io::Error>
    where
        F: FnMut(StreamingScanEvent),
    {
        // Canonicalize path to prevent directory traversal attacks
        // Defense-in-depth: validates even if CLI layer already canonicalized
        let canonical_path = canonicalize_path(root_path)?;
        let path_str = canonical_path.to_string_lossy();

        let mut files_scanned = 0;
        let mut dirs_scanned = 0;

        // Skip file estimation to avoid blocking - start scanning immediately
        let estimated_total = None;

        // Scan for libraries
        // Disable symlink following to prevent symlink loops and boundary escapes
        let mut walker = WalkDir::new(path_str.as_ref()).follow_links(false);
        if let Some(depth) = max_depth {
            walker = walker.max_depth(depth);
        }

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            if path.is_dir() {
                dirs_scanned += 1;
            } else {
                files_scanned += 1;
            }

            // Send progress update every 10 files for more responsive UI
            if files_scanned % 10 == 0 {
                callback(StreamingScanEvent::Progress {
                    files_scanned,
                    dirs_scanned,
                    estimated_total,
                    current_path: path.to_path_buf(),
                });
            }

            if !path.is_file() {
                continue;
            }

            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Check for library files
            if self.is_library_file(filename) {
                if let Some((crypto_name, crypto_type)) = self.identify_crypto_library(filename) {
                    let finding = CryptoFinding {
                        path: path.display().to_string(),
                        name: filename.to_string(),
                        finding_type: if filename.ends_with(".a") {
                            FindingType::StaticLibrary
                        } else {
                            FindingType::BinaryLibrary
                        },
                        crypto_type,
                        ecosystem: Ecosystem::System,
                        version: None,
                        version_source: VersionSource::Declared,
                        details: format!("Detected: {}", crypto_name),
                    };

                    let library_info = self.finding_to_library_info(&finding);
                    self.findings.push(finding);
                    callback(StreamingScanEvent::LibraryFound(library_info));
                }
            }

            // Check for manifests
            match filename {
                "Cargo.toml" => {
                    if let Ok(()) = self.scan_cargo_toml_streaming(path, &mut callback) {
                        // Findings already reported via callback
                    }
                }
                "package.json" => {
                    if let Ok(()) = self.scan_package_json_streaming(path, &mut callback) {
                        // Findings already reported via callback
                    }
                }
                "requirements.txt" => {
                    if let Ok(()) = self.scan_requirements_txt_streaming(path, &mut callback) {
                        // Findings already reported via callback
                    }
                }
                "pyproject.toml" => {
                    if let Ok(()) = self.scan_pyproject_toml_streaming(path, &mut callback) {
                        // Findings already reported via callback
                    }
                }
                "Pipfile" => {
                    if let Ok(()) = self.scan_pipfile_streaming(path, &mut callback) {
                        // Findings already reported via callback
                    }
                }
                _ => {}
            }
        }

        // Final progress update
        callback(StreamingScanEvent::Progress {
            files_scanned,
            dirs_scanned,
            estimated_total,
            current_path: PathBuf::from(root_path),
        });

        callback(StreamingScanEvent::Complete {
            total_libraries: self.findings.len(),
        });

        Ok(())
    }

    /// Streaming version of scan_cargo_toml
    fn scan_cargo_toml_streaming<F>(&mut self, path: &Path, callback: &mut F) -> Result<(), std::io::Error>
    where
        F: FnMut(StreamingScanEvent),
    {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // File too large, skip silently
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let parsed = match toml::from_str::<toml::Value>(&content) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        let crypto_crates = cargo_crypto_crates();
        let lock = crate::lockfile::resolve_from_sibling_lock(path);
        let mut declared: std::collections::HashSet<&str> = std::collections::HashSet::new();

        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_table()) {
            for (crate_name, crypto_type) in &crypto_crates {
                if let Some(dep_value) = deps.get(*crate_name) {
                    declared.insert(*crate_name);
                    let (version, version_source) = resolve_version(
                        extract_toml_version(dep_value),
                        lock.as_ref().and_then(|l| l.get(*crate_name).cloned()),
                    );
                    let finding = CryptoFinding {
                        path: path.display().to_string(),
                        name: crate_name.to_string(),
                        finding_type: FindingType::DependencyManifest,
                        crypto_type: crypto_type.clone(),
                        ecosystem: Ecosystem::Cargo,
                        version,
                        version_source,
                        details: format!("Rust crate dependency: {}", crate_name),
                    };

                    let library_info = self.finding_to_library_info(&finding);
                    self.findings.push(finding);
                    callback(StreamingScanEvent::LibraryFound(library_info));
                }
            }
        }

        // Transitive crypto resolved from a sibling Cargo.lock.
        if let Some(lock) = lock.as_ref() {
            for (crate_name, crypto_type) in &crypto_crates {
                if declared.contains(*crate_name) {
                    continue;
                }
                if let Some(version) = lock.get(*crate_name) {
                    let finding = CryptoFinding {
                        path: path.display().to_string(),
                        name: crate_name.to_string(),
                        finding_type: FindingType::TransitiveDependency,
                        crypto_type: crypto_type.clone(),
                        ecosystem: Ecosystem::Cargo,
                        version: Some(version.clone()),
                        version_source: VersionSource::Locked,
                        details: format!("Transitive Rust crate (from Cargo.lock): {}", crate_name),
                    };

                    let library_info = self.finding_to_library_info(&finding);
                    self.findings.push(finding);
                    callback(StreamingScanEvent::LibraryFound(library_info));
                }
            }
        }

        Ok(())
    }

    /// Streaming version of scan_package_json
    fn scan_package_json_streaming<F>(&mut self, path: &Path, callback: &mut F) -> Result<(), std::io::Error>
    where
        F: FnMut(StreamingScanEvent),
    {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // File too large, skip silently
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(parsed) => {
                let crypto_packages = npm_crypto_packages();
                let lock = crate::lockfile::resolve_npm_from_sibling_lock(path);

                let mut declared: std::collections::HashSet<&str> = std::collections::HashSet::new();

                if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
                    for (pkg_name, crypto_type) in &crypto_packages {
                        if let Some(ver_value) = deps.get(*pkg_name) {
                            declared.insert(*pkg_name);
                            let (version, version_source) = resolve_version(
                                ver_value.as_str().and_then(clean_version_req),
                                lock.as_ref().and_then(|l| l.get(*pkg_name).cloned()),
                            );
                            let finding = CryptoFinding {
                                path: path.display().to_string(),
                                name: pkg_name.to_string(),
                                finding_type: FindingType::DependencyManifest,
                                crypto_type: crypto_type.clone(),
                                ecosystem: Ecosystem::Npm,
                                version,
                                version_source,
                                details: format!("Node.js package dependency: {}", pkg_name),
                            };

                            let library_info = self.finding_to_library_info(&finding);
                            self.findings.push(finding);
                            callback(StreamingScanEvent::LibraryFound(library_info));
                        }
                    }
                }

                if let Some(lock) = lock.as_ref() {
                    for (pkg_name, crypto_type) in &crypto_packages {
                        if declared.contains(*pkg_name) {
                            continue;
                        }
                        if let Some(version) = lock.get(*pkg_name) {
                            let finding = CryptoFinding {
                                path: path.display().to_string(),
                                name: pkg_name.to_string(),
                                finding_type: FindingType::TransitiveDependency,
                                crypto_type: crypto_type.clone(),
                                ecosystem: Ecosystem::Npm,
                                version: Some(version.clone()),
                                version_source: VersionSource::Locked,
                                details: format!("Transitive Node.js package (from package-lock.json): {}", pkg_name),
                            };

                            let library_info = self.finding_to_library_info(&finding);
                            self.findings.push(finding);
                            callback(StreamingScanEvent::LibraryFound(library_info));
                        }
                    }
                }
            }
            Err(_) => {}
        }

        Ok(())
    }

    /// Streaming version of scan_requirements_txt
    fn scan_requirements_txt_streaming<F>(&mut self, path: &Path, callback: &mut F) -> Result<(), std::io::Error>
    where
        F: FnMut(StreamingScanEvent),
    {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // File too large, skip silently
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        for finding in pypi_findings_from_requirements(&content, path) {
            let library_info = self.finding_to_library_info(&finding);
            self.findings.push(finding);
            callback(StreamingScanEvent::LibraryFound(library_info));
        }

        Ok(())
    }

    /// Streaming version of scan_pyproject_toml
    fn scan_pyproject_toml_streaming<F>(&mut self, path: &Path, callback: &mut F) -> Result<(), std::io::Error>
    where
        F: FnMut(StreamingScanEvent),
    {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Ok(()),
            Err(e) => return Err(e),
        };
        let parsed = match toml::from_str::<toml::Value>(&content) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let declared = pyproject_declared_names(&parsed);
        let lock = crate::lockfile::resolve_pypi_from_sibling_lock(path);
        for finding in pypi_findings_from_manifest(path, &declared, lock.as_ref()) {
            let library_info = self.finding_to_library_info(&finding);
            self.findings.push(finding);
            callback(StreamingScanEvent::LibraryFound(library_info));
        }
        Ok(())
    }

    /// Streaming version of scan_pipfile
    fn scan_pipfile_streaming<F>(&mut self, path: &Path, callback: &mut F) -> Result<(), std::io::Error>
    where
        F: FnMut(StreamingScanEvent),
    {
        let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Ok(()),
            Err(e) => return Err(e),
        };
        let parsed = match toml::from_str::<toml::Value>(&content) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let declared = pipfile_declared_names(&parsed);
        let lock = crate::lockfile::resolve_pypi_from_sibling_lock(path);
        for finding in pypi_findings_from_manifest(path, &declared, lock.as_ref()) {
            let library_info = self.finding_to_library_info(&finding);
            self.findings.push(finding);
            callback(StreamingScanEvent::LibraryFound(library_info));
        }
        Ok(())
    }
}

/// Events emitted during streaming scan
pub enum StreamingScanEvent {
    Progress {
        files_scanned: usize,
        dirs_scanned: usize,
        estimated_total: Option<usize>,
        current_path: PathBuf,
    },
    LibraryFound(crate::library::LibraryInfo),
    Complete {
        total_libraries: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn pep503_normalization() {
        assert_eq!(normalize_pypi_name("PyOpenSSL"), "pyopenssl");
        assert_eq!(normalize_pypi_name("PyNaCl"), "pynacl");
        assert_eq!(normalize_pypi_name("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(normalize_pypi_name("foo__bar..baz"), "foo-bar-baz");
        assert_eq!(normalize_pypi_name("  Cryptography  "), "cryptography");
        // PEP 503 is `re.sub(r"[-_.]+", "-", name).lower()` — it collapses runs
        // but does NOT strip leading or trailing separators. PEP 508 forbids
        // names shaped this way, yet the OSV malware feed ships them (e.g.
        // `urlcon-`), and diverging from the published formula would key them
        // differently from every other consumer.
        assert_eq!(normalize_pypi_name("urlcon-"), "urlcon-");
        assert_eq!(normalize_pypi_name("-lead"), "-lead");
        assert_eq!(normalize_pypi_name("trail___"), "trail-");
    }

    #[test]
    fn pep508_name_extraction() {
        assert_eq!(pep508_name("cryptography>=41.0"), Some("cryptography"));
        assert_eq!(pep508_name("PyNaCl==1.5.0 ; python_version>='3.8'"), Some("PyNaCl"));
        assert_eq!(pep508_name("bcrypt[extra]"), Some("bcrypt"));
        assert_eq!(pep508_name(">=1.0"), None);
    }

    #[test]
    fn requirements_exact_pin_is_locked_others_declared() {
        let content = "\
cryptography==41.0.7
PyNaCl>=1.5.0
# a comment
-r other.txt
bcrypt==4.1.2  # inline comment
requests==2.31.0
";
        let findings = pypi_findings_from_requirements(content, Path::new("/p/requirements.txt"));

        let crypto = findings.iter().find(|f| f.name == "cryptography").unwrap();
        assert_eq!(crypto.version.as_deref(), Some("41.0.7"));
        assert_eq!(crypto.version_source, VersionSource::Locked);

        let nacl = findings.iter().find(|f| f.name == "pynacl").unwrap();
        assert_eq!(nacl.version_source, VersionSource::Declared);

        let bcrypt = findings.iter().find(|f| f.name == "bcrypt").unwrap();
        assert_eq!(bcrypt.version.as_deref(), Some("4.1.2"), "inline comment stripped");
        assert_eq!(bcrypt.version_source, VersionSource::Locked);

        // Non-crypto package is ignored.
        assert!(findings.iter().all(|f| f.name != "requests"));
    }

    #[test]
    fn manifest_split_declared_vs_transitive() {
        let mut declared = std::collections::HashSet::new();
        declared.insert("cryptography".to_string());

        let mut lock = HashMap::new();
        lock.insert("cryptography".to_string(), "41.0.7".to_string());
        lock.insert("pynacl".to_string(), "1.5.0".to_string()); // transitive (not declared)

        let findings =
            pypi_findings_from_manifest(Path::new("/p/pyproject.toml"), &declared, Some(&lock));

        let crypto = findings.iter().find(|f| f.name == "cryptography").unwrap();
        assert_eq!(crypto.finding_type, FindingType::DependencyManifest);
        assert_eq!(crypto.version.as_deref(), Some("41.0.7"));
        assert_eq!(crypto.version_source, VersionSource::Locked);

        let nacl = findings.iter().find(|f| f.name == "pynacl").unwrap();
        assert_eq!(nacl.finding_type, FindingType::TransitiveDependency);
        assert_eq!(nacl.version_source, VersionSource::Locked);
    }

    #[test]
    fn pyproject_declared_names_poetry_and_pep621() {
        let poetry = toml::from_str::<toml::Value>(
            "[tool.poetry.dependencies]\ncryptography = \"^41.0\"\n[tool.poetry.group.dev.dependencies]\nbcrypt = \"*\"\n",
        )
        .unwrap();
        let names = pyproject_declared_names(&poetry);
        assert!(names.contains("cryptography"));
        assert!(names.contains("bcrypt"));

        let pep621 = toml::from_str::<toml::Value>(
            "[project]\ndependencies = [\"PyNaCl>=1.5\", \"requests\"]\n",
        )
        .unwrap();
        let names = pyproject_declared_names(&pep621);
        assert!(names.contains("pynacl"));
        assert!(names.contains("requests"));
    }
}
