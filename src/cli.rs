//! Command-line interface for 3329lens.
//!
//! Two subcommands: `scan` for batch output (text/JSON/CBOM/SARIF) and
//! `scanner-dashboard` for the interactive TUI.

use clap::{Parser, Subcommand};
use colored::*;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

use scanner_core::scanner::CryptoScanner;

/// Canonicalize and validate a user-provided path to prevent directory traversal attacks.
///
/// This function:
/// - Resolves relative paths to absolute paths
/// - Resolves `.` and `..` components
/// - Resolves symlinks (providing defense-in-depth with follow_links(false))
/// - Validates the path exists
///
/// Returns an error if the path doesn't exist or cannot be canonicalized.
fn canonicalize_scan_path(path: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use std::path::Path;

    let input_path = Path::new(path);

    // Canonicalize resolves:
    // - Relative paths (./foo, foo) to absolute paths
    // - Parent references (../bar)
    // - Symlinks (defense-in-depth)
    // - Returns error if path doesn't exist
    let canonical = std::fs::canonicalize(input_path)
        .map_err(|e| format!("Cannot access path '{}': {}", path, e))?;

    // Additional validation: ensure it's a directory (for scanning purposes)
    if !canonical.is_dir() {
        return Err(format!("Path '{}' is not a directory", canonical.display()).into());
    }

    Ok(canonical)
}

#[derive(Parser)]
#[command(name = "3329lens")]
#[command(about = "Cryptographic inventory scanner — discovery, CVE correlation, CBOM/SARIF export")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan filesystem for cryptographic libraries and dependencies
    Scan {
        /// Path to scan
        #[arg(short, long, default_value = ".")]
        path: String,
        /// Maximum depth for recursive scanning
        #[arg(short, long)]
        depth: Option<usize>,
        /// Output format: text, json, cbom (CycloneDX 1.6), sarif (SARIF 2.1.0)
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
        /// Save results to file
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Path to a local advisory database (RustSec advisory-db clone and/or
        /// OSV JSON) for offline CVE correlation against resolved versions
        #[arg(long)]
        advisory_db: Option<String>,
        /// Exit non-zero if a vulnerability at or above this severity is found:
        /// none, low, medium, high, critical
        #[arg(long, default_value = "none")]
        fail_on: String,
    },
    /// Interactive scanner dashboard for cryptographic library discovery
    ScannerDashboard {
        /// Path to scan
        #[arg(short, long, default_value = ".")]
        path: String,
        /// Maximum depth for recursive scanning
        #[arg(short, long)]
        depth: Option<usize>,
        /// Refresh rate in FPS (frames per second)
        #[arg(long, default_value = "30")]
        refresh_rate: u64,
    },
}

/// Dispatch a parsed command.
pub fn run(cmd: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Commands::Scan { path, depth, format, output, advisory_db, fail_on } => {
            handle_scan(&path, depth, &format, output.as_deref(), advisory_db.as_deref(), &fail_on)
        }
        Commands::ScannerDashboard { path, depth, refresh_rate } => {
            handle_scanner_dashboard(&path, depth, refresh_rate)
        }
    }
}

fn handle_scan(path: &str, depth: Option<usize>, format: &str, output: Option<&str>, advisory_db: Option<&str>, fail_on: &str) -> Result<(), Box<dyn std::error::Error>> {
    use scanner_core::advisories::{AdvisoryDb, CorrelationResult, Severity};

    // Parse the CI gating threshold up front so an invalid value fails fast.
    let fail_threshold = Severity::parse(fail_on).ok_or_else(|| {
        format!("Invalid --fail-on value '{}'. Use: none, low, medium, high, critical.", fail_on)
    })?;
    // Canonicalize path to prevent directory traversal attacks
    // This resolves ../../../etc type paths and validates existence
    let canonical_path = canonicalize_scan_path(path)?;
    let path_str = canonical_path.to_string_lossy();

    println!("{}", format!("🔍 Scanning for cryptographic libraries in: {}", path_str).bold().cyan());
    if path != path_str.as_ref() {
        println!("  (resolved from: {})", path.italic());
    }

    if let Some(d) = depth {
        println!("  Max depth: {}", d.to_string().yellow());
    } else {
        println!("  Max depth: {}", "unlimited".yellow());
    }

    let mut scanner = CryptoScanner::new();

    // Run the scan with canonicalized path
    let start = Instant::now();
    scanner.scan(&path_str, depth)?;
    let duration = start.elapsed();

    let findings = scanner.get_findings();
    let stats = scanner.get_statistics();

    println!("\n{}", format!("✅ Scan complete in {:.2}s", duration.as_secs_f64()).bold().green());
    println!("\n{}", "📊 Statistics:".bold().yellow());
    println!("  Total findings: {}", stats.get("total").unwrap_or(&0).to_string().cyan());
    println!("  Binary libraries: {}", stats.get("binary_libraries").unwrap_or(&0).to_string().cyan());
    println!("  Static libraries: {}", stats.get("static_libraries").unwrap_or(&0).to_string().cyan());
    println!("  Dependency manifests: {}", stats.get("manifests").unwrap_or(&0).to_string().cyan());
    println!("\n{}", "🔐 By Category:".bold().yellow());
    println!("  SSL/TLS: {}", stats.get("ssl_tls").unwrap_or(&0).to_string().green());
    println!("  General Crypto: {}", stats.get("general_crypto").unwrap_or(&0).to_string().green());
    println!("  Post-Quantum: {}", stats.get("post_quantum").unwrap_or(&0).to_string().magenta());
    let transitive = *stats.get("transitive").unwrap_or(&0);
    if transitive > 0 {
        println!("  Transitive (from lockfiles): {}", transitive.to_string().cyan());
    }

    // Optional advisory / CVE correlation against lockfile-resolved versions.
    let correlation: Option<CorrelationResult> = match advisory_db {
        Some(db_path) => {
            let db = AdvisoryDb::load_from_dir(std::path::Path::new(db_path))?;
            println!("\n{}", format!("🛡️  Loaded {} advisories from {}", db.len(), db_path).bold().cyan());
            let result = scanner_core::advisories::correlate(&db, findings);

            println!("\n{}", "🛡️  Vulnerabilities (resolved versions only):".bold().yellow());
            if result.matches.is_empty() {
                println!("  {}", "No known vulnerabilities matched.".green());
            } else {
                for (severity, count) in result.counts_by_severity() {
                    let label = format!("  {}: {}", severity.as_str(), count);
                    println!("{}", match severity {
                        Severity::Critical | Severity::High => label.red(),
                        Severity::Medium => label.yellow(),
                        _ => label.normal(),
                    });
                }
                for m in &result.matches {
                    for adv in &m.advisories {
                        println!("    {} {}@{} — {} ({})",
                            "•".red(),
                            m.name.bold(),
                            m.version,
                            adv.id.yellow(),
                            adv.severity.as_str());
                    }
                }
            }
            if result.skipped_unresolved > 0 {
                println!("  {}", format!("ℹ️  {} declared dependency(ies) had unresolved versions (no lockfile) — advisory check skipped.", result.skipped_unresolved).italic());
            }
            Some(result)
        }
        None => None,
    };

    // Output results
    match format {
        "json" => {
            // Backward-compatible: bare findings array unless advisory
            // correlation was requested, in which case emit a combined
            // object so consumers get both findings and vulnerabilities.
            let json_output = match &correlation {
                Some(result) => serde_json::to_string_pretty(&serde_json::json!({
                    "findings": findings,
                    "vulnerabilities": result.matches,
                    "skipped_unresolved": result.skipped_unresolved,
                }))?,
                None => serde_json::to_string_pretty(findings)?,
            };

            if let Some(output_path) = output {
                let mut file = File::create(output_path)?;
                file.write_all(json_output.as_bytes())?;
                println!("\n{}", format!("💾 Results saved to: {}", output_path).green());
            } else {
                println!("\n{}", "📄 JSON Output:".bold().yellow());
                println!("{}", json_output);
            }
        }
        "text" => {
            if !findings.is_empty() {
                println!("\n{}", "🔍 Detailed Findings:".bold().yellow());

                for (i, finding) in findings.iter().enumerate() {
                    let type_icon = match finding.finding_type {
                        scanner_core::scanner::FindingType::BinaryLibrary => "📚",
                        scanner_core::scanner::FindingType::StaticLibrary => "📦",
                        scanner_core::scanner::FindingType::DependencyManifest => "📝",
                        scanner_core::scanner::FindingType::TransitiveDependency => "🔗",
                        scanner_core::scanner::FindingType::SourceCode => "💻",
                    };

                    let crypto_color = match finding.crypto_type {
                        scanner_core::scanner::CryptoType::SSL_TLS => "green",
                        scanner_core::scanner::CryptoType::GeneralCrypto => "cyan",
                        scanner_core::scanner::CryptoType::PostQuantum => "magenta",
                        scanner_core::scanner::CryptoType::HashFunction => "yellow",
                        scanner_core::scanner::CryptoType::Unknown => "white",
                    };

                    println!("\n{}. {} {}",
                        (i + 1).to_string().bold(),
                        type_icon,
                        finding.path.color(crypto_color)
                    );
                    println!("   {}", finding.details.italic());
                }

                if let Some(output_path) = output {
                    let mut file = File::create(output_path)?;
                    for finding in findings {
                        writeln!(file, "{:?}", finding)?;
                    }
                    println!("\n{}", format!("💾 Results saved to: {}", output_path).green());
                }
            } else {
                println!("\n{}", "ℹ️  No cryptographic libraries found in the specified path.".yellow());
            }
        }
        "cbom" => {
            let mut bom = scanner_core::cbom::findings_to_cbom(findings, &path_str);

            // Stamp a v4 serial number. This needs uniqueness, not
            // cryptographic strength, so the OS entropy source is sufficient.
            let mut uuid_bytes = [0u8; 16];
            getrandom::getrandom(&mut uuid_bytes)?;
            bom.serial_number = Some(format!("urn:uuid:{}", scanner_core::cbom::format_uuid_v4(uuid_bytes)));

            // Quick summary of inferred algorithm assets and quantum exposure.
            let crypto_assets = bom.components.iter()
                .filter(|c| c.component_type == scanner_core::cbom::ComponentType::CryptographicAsset)
                .count();
            let quantum_vulnerable = bom.components.iter()
                .filter_map(|c| c.crypto_properties.as_ref())
                .filter_map(|p| p.algorithm_properties.as_ref())
                .filter(|a| a.nist_quantum_security_level == Some(0))
                .count();
            println!("\n{}", "🧬 Inferred Cryptographic Assets:".bold().yellow());
            println!("  Algorithms: {}", crypto_assets.to_string().cyan());
            println!("  Quantum-vulnerable (Shor-breakable): {}", quantum_vulnerable.to_string().red());

            // Attach correlated advisories to CycloneDX's native
            // `vulnerabilities` array, linked to the affected library.
            if let Some(result) = &correlation {
                for m in &result.matches {
                    let bom_ref = bom.library_ref(&m.name, Some(&m.version));
                    for adv in &m.advisories {
                        bom.vulnerabilities.push(scanner_core::cbom::Vulnerability {
                            id: adv.id.clone(),
                            ratings: vec![scanner_core::cbom::Rating {
                                score: adv.cvss,
                                severity: adv.severity.as_str().to_string(),
                                method: adv.cvss.map(|_| "CVSSv3".to_string()),
                            }],
                            description: if adv.title.is_empty() { None } else { Some(adv.title.clone()) },
                            affects: bom_ref.iter()
                                .map(|r| scanner_core::cbom::Affects { bom_ref: r.clone() })
                                .collect(),
                        });
                    }
                }
            }

            let json_output = serde_json::to_string_pretty(&bom)?;

            if let Some(output_path) = output {
                let mut file = File::create(output_path)?;
                file.write_all(json_output.as_bytes())?;
                println!("\n{}", format!("💾 CycloneDX CBOM saved to: {}", output_path).green());
            } else {
                println!("\n{}", "📄 CycloneDX CBOM (1.6):".bold().yellow());
                println!("{}", json_output);
            }
        }
        "sarif" => {
            // SARIF carries correlated vulnerabilities only. Without an
            // advisory DB there is nothing to report, so emit a valid but
            // empty run and hint at how to populate it.
            if advisory_db.is_none() {
                println!("\n{}", "ℹ️  SARIF output reports correlated vulnerabilities; pass --advisory-db to populate results.".italic());
            }

            let empty = CorrelationResult::default();
            let correlation_ref = correlation.as_ref().unwrap_or(&empty);
            let log = scanner_core::sarif::build(correlation_ref, &path_str);
            let json_output = serde_json::to_string_pretty(&log)?;

            if let Some(output_path) = output {
                let mut file = File::create(output_path)?;
                file.write_all(json_output.as_bytes())?;
                println!("\n{}", format!("💾 SARIF 2.1.0 saved to: {}", output_path).green());
            } else {
                println!("\n{}", "📄 SARIF (2.1.0):".bold().yellow());
                println!("{}", json_output);
            }
        }
        _ => {
            return Err(format!("Unknown output format: {}. Use 'text', 'json', 'cbom', or 'sarif'.", format).into());
        }
    }

    // CI gating: exit non-zero (code 2, distinct from operational errors)
    // when a vulnerability at or above the configured threshold was found.
    if fail_threshold > Severity::None {
        if let Some(worst) = correlation.as_ref().and_then(|r| r.worst_severity()) {
            if worst >= fail_threshold {
                eprintln!(
                    "\n❌ Vulnerability gate failed: found {} severity (threshold: {}).",
                    worst.as_str(),
                    fail_threshold.as_str()
                );
                std::process::exit(2);
            }
        }
    }

    Ok(())
}

fn handle_scanner_dashboard(path: &str, depth: Option<usize>, refresh_rate: u64) -> Result<(), Box<dyn std::error::Error>> {
    // Canonicalize path to prevent directory traversal attacks
    // This resolves ../../../etc type paths and validates existence
    let canonical_path = canonicalize_scan_path(path)?;

    println!("{}", "🔍 Starting Scanner Dashboard...".bold().cyan());
    println!("{}", format!("  Scanning: {}", canonical_path.display()).italic());
    if path != canonical_path.to_string_lossy().as_ref() {
        println!("{}", format!("  (resolved from: {})", path).italic());
    }
    if let Some(d) = depth {
        println!("{}", format!("  Max depth: {}", d).italic());
    }
    println!("{}", "  Press 'q' or Esc to quit".italic());
    println!();

    // Small delay for user to read the message
    std::thread::sleep(std::time::Duration::from_millis(1000));

    let config = crate::scanner_dashboard::ScannerDashboardConfig {
        path: canonical_path,
        depth,
        refresh_rate,
    };

    crate::scanner_dashboard::run_scanner_dashboard(config)?;

    println!("\n{}", "✓ Scanner Dashboard closed".green());
    Ok(())
}
