/*
 * Advisory / CVE Correlation Module - Defensive Security
 *
 * Correlates lockfile-resolved dependency versions against a vulnerability
 * database, turning a passive inventory into an actionable risk signal that can
 * gate CI.
 *
 * Design principles:
 *   - Offline-first: the database is read from a local directory (a RustSec
 *     `advisory-db` clone and/or OSV JSON export). No network calls are made.
 *   - Evidence-based only: correlation runs against `VersionSource::Locked`
 *     findings. Declared-but-unresolved versions are counted as skipped rather
 *     than guessed, so we never emit false confidence.
 *
 * Scope: crates.io (RustSec TOML + OSV), npm and PyPI (OSV JSON). Advisories
 * are indexed by `(ecosystem, package)` so a name shared across ecosystems
 * (e.g. `cryptography` on PyPI vs. a same-named npm package) cannot cross-match.
 * OSV JSON is parsed for single-range advisories. This is a teaching-grade
 * correlator, not a replacement for `cargo audit` / a commercial scanner.
 *
 * Version comparison is ecosystem-aware: crates.io and npm versions are semver
 * and use `semver::Version`; PyPI versions use the PEP 440 scheme via the
 * `pep440` module, so pre/post/dev releases, epochs, short release segments
 * (`3.1`), and local versions all compare correctly. A version that fails its
 * ecosystem's parser matches nothing rather than being guessed.
 *
 * Part of the Slow Lynx Cryptography Discovery project.
 */

use std::collections::HashMap;
use std::path::Path;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::pep440;
use crate::scanner::{read_file_with_limit, CryptoFinding, Ecosystem, VersionSource, MAX_MANIFEST_SIZE};

/// A version parsed under its ecosystem's scheme: semver for crates.io and
/// npm, PEP 440 for PyPI. Parsing once up front lets every advisory for the
/// package reuse the parse, and keeps the scheme choice in one place.
#[derive(Debug, Clone)]
pub enum ParsedVersion {
    Semver(Version),
    Pep440(pep440::Version),
}

impl ParsedVersion {
    /// Parse `version` under `ecosystem`'s scheme. `None` means the version is
    /// outside the scheme and must match nothing (we never guess).
    pub fn parse(ecosystem: &Ecosystem, version: &str) -> Option<ParsedVersion> {
        match ecosystem {
            Ecosystem::PyPI => pep440::Version::parse(version).map(ParsedVersion::Pep440),
            _ => Version::parse(version).ok().map(ParsedVersion::Semver),
        }
    }

    /// Does this version satisfy a single requirement string (e.g. `>= 1.2.0`)?
    /// An unparseable requirement matches nothing.
    fn satisfies(&self, req: &str) -> bool {
        match self {
            ParsedVersion::Semver(v) => VersionReq::parse(req)
                .map(|r| r.matches(v))
                .unwrap_or(false),
            ParsedVersion::Pep440(v) => pep440::Requirement::parse(req)
                .map(|r| r.matches(v))
                .unwrap_or(false),
        }
    }
}

/// Qualitative severity, ordered so `>=` threshold comparisons work for CI
/// gating. Variant order is significant: `None < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Map a CVSS base score to a qualitative severity (FIRST.org bands).
    pub fn from_score(score: f32) -> Severity {
        if score <= 0.0 {
            Severity::None
        } else if score < 4.0 {
            Severity::Low
        } else if score < 7.0 {
            Severity::Medium
        } else if score < 9.0 {
            Severity::High
        } else {
            Severity::Critical
        }
    }

    /// Parse a `--fail-on` threshold or textual severity (case-insensitive).
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_lowercase().as_str() {
            "none" => Some(Severity::None),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Lowercase label, matching CycloneDX vulnerability rating severities.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// A single advisory affecting a package over some version range(s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    /// Ecosystem the advisory applies to. Part of the index key so same-named
    /// packages in different ecosystems never cross-match.
    pub ecosystem: Ecosystem,
    pub package: String,
    pub title: String,
    pub severity: Severity,
    /// CVSS base score when derivable from a CVSS v3 vector, else `None`.
    pub cvss: Option<f32>,
    /// semver requirement strings considered *patched* (fixed).
    patched: Vec<String>,
    /// semver requirement strings explicitly *unaffected*.
    unaffected: Vec<String>,
}

impl Advisory {
    /// Is `version` affected? A version is affected when it satisfies neither a
    /// patched range nor an explicitly-unaffected range.
    pub fn affects(&self, version: &ParsedVersion) -> bool {
        let satisfies = |reqs: &[String]| reqs.iter().any(|r| version.satisfies(r));
        !satisfies(&self.patched) && !satisfies(&self.unaffected)
    }

    /// Construct a minimal advisory for tests in other modules (e.g. SARIF
    /// output), which cannot reach the private `patched`/`unaffected` fields.
    #[cfg(test)]
    pub(crate) fn for_test(id: &str, severity: Severity, cvss: Option<f32>, title: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            ecosystem: Ecosystem::Cargo,
            package: id.to_string(),
            title: title.to_string(),
            severity,
            cvss,
            patched: Vec::new(),
            unaffected: Vec::new(),
        }
    }
}

/// An offline vulnerability database indexed by `(ecosystem, package name)`.
#[derive(Debug, Default)]
pub struct AdvisoryDb {
    by_package: HashMap<(Ecosystem, String), Vec<Advisory>>,
}

impl AdvisoryDb {
    /// Recursively load advisories from a local directory. `.md` and `.toml`
    /// files are parsed as RustSec advisories, `.json` as OSV. Unparseable files
    /// are skipped. Reuses the scanner's DoS-guarded reader.
    ///
    /// `.md` is the format the real `rustsec/advisory-db` repository actually
    /// ships: a fenced ```` ```toml ```` block followed by markdown prose. At the
    /// time of writing that clone contains 1,217 such files and a single bare
    /// `.toml`, so extension-matching on `toml` alone silently loads nothing.
    /// Non-advisory markdown in the repo (README, contributor guides) has no
    /// leading TOML block and is skipped by the parser rather than special-cased.
    pub fn load_from_dir(path: &Path) -> std::io::Result<AdvisoryDb> {
        let mut db = AdvisoryDb::default();
        for entry in WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            match p.extension().and_then(|e| e.to_str()) {
                Some("toml") | Some("md") => {
                    if let Some(a) = parse_rustsec_advisory(p) {
                        db.insert(a);
                    }
                }
                Some("json") => {
                    for a in parse_osv_json(p) {
                        db.insert(a);
                    }
                }
                _ => {}
            }
        }
        Ok(db)
    }

    fn insert(&mut self, a: Advisory) {
        self.by_package
            .entry((a.ecosystem.clone(), a.package.clone()))
            .or_default()
            .push(a);
    }

    /// Advisories affecting `name` at `version` within `ecosystem`. The version
    /// is parsed under the ecosystem's scheme (semver, or PEP 440 for PyPI); an
    /// unparseable version matches nothing (we never guess).
    pub fn matches(&self, ecosystem: &Ecosystem, name: &str, version: &str) -> Vec<&Advisory> {
        let parsed = match ParsedVersion::parse(ecosystem, version) {
            Some(v) => v,
            None => return Vec::new(),
        };
        self.by_package
            .get(&(ecosystem.clone(), name.to_string()))
            .map(|advs| advs.iter().filter(|a| a.affects(&parsed)).collect())
            .unwrap_or_default()
    }

    /// Total number of advisories loaded.
    pub fn len(&self) -> usize {
        self.by_package.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_package.is_empty()
    }
}

/// A finding paired with the advisories that affect it.
#[derive(Debug, Clone, Serialize)]
pub struct FindingMatch {
    pub name: String,
    pub version: String,
    /// Source path of the originating finding (manifest or lockfile). Used to
    /// give SARIF results a `physicalLocation`.
    pub path: String,
    pub advisories: Vec<Advisory>,
}

/// Outcome of correlating a set of findings against the advisory DB.
#[derive(Debug, Default)]
pub struct CorrelationResult {
    pub matches: Vec<FindingMatch>,
    /// Findings with a declared-but-unresolved version (no lockfile) that were
    /// therefore not advisory-checked.
    pub skipped_unresolved: usize,
}

impl CorrelationResult {
    /// Highest severity across all matched advisories, if any.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.matches
            .iter()
            .flat_map(|m| m.advisories.iter())
            .map(|a| a.severity)
            .max()
    }

    /// Total advisory count across all matched findings.
    pub fn total_advisories(&self) -> usize {
        self.matches.iter().map(|m| m.advisories.len()).sum()
    }

    /// Advisory counts bucketed by severity (highest first for display).
    pub fn counts_by_severity(&self) -> Vec<(Severity, usize)> {
        let mut counts: HashMap<Severity, usize> = HashMap::new();
        for adv in self.matches.iter().flat_map(|m| m.advisories.iter()) {
            *counts.entry(adv.severity).or_insert(0) += 1;
        }
        let mut out: Vec<_> = counts.into_iter().collect();
        out.sort_by(|a, b| b.0.cmp(&a.0));
        out
    }
}

/// Correlate findings against the DB. Only `VersionSource::Locked` findings with
/// a concrete version are checked; declared-only versioned findings are tallied
/// as skipped.
pub fn correlate(db: &AdvisoryDb, findings: &[CryptoFinding]) -> CorrelationResult {
    let mut result = CorrelationResult::default();
    // De-duplicate by (ecosystem, name, version) so a transitively+directly seen
    // package is only reported once — and so a same-named package in a different
    // ecosystem is not collapsed away.
    let mut seen: std::collections::HashSet<(Ecosystem, String, String)> =
        std::collections::HashSet::new();

    for finding in findings {
        let version = match &finding.version {
            Some(v) => v,
            None => continue,
        };
        match finding.version_source {
            VersionSource::Locked => {
                if !seen.insert((
                    finding.ecosystem.clone(),
                    finding.name.clone(),
                    version.clone(),
                )) {
                    continue;
                }
                let advisories: Vec<Advisory> = db
                    .matches(&finding.ecosystem, &finding.name, version)
                    .into_iter()
                    .cloned()
                    .collect();
                if !advisories.is_empty() {
                    result.matches.push(FindingMatch {
                        name: finding.name.clone(),
                        version: version.clone(),
                        path: finding.path.clone(),
                        advisories,
                    });
                }
            }
            VersionSource::Declared => {
                result.skipped_unresolved += 1;
            }
        }
    }
    result
}

/// Split a RustSec advisory file into its TOML metadata and its markdown body.
///
/// Real advisories are markdown: a fenced ```` ```toml ```` block, then prose
/// whose first `# ` heading is the advisory title. A file that is entirely TOML
/// (the hand-written fixture shape, and one file in the real repo) is returned
/// as-is with no body. Returns `None` for markdown with no leading TOML block,
/// which is how the repo's README and contributor guides get skipped.
fn split_advisory_frontmatter(content: &str) -> Option<(&str, &str)> {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("```") {
        // No fence: treat the whole file as TOML. Bare-TOML advisories have no
        // markdown body, so the title must come from the TOML itself.
        return Some((content, ""));
    }

    // Step over the opening fence line (```toml, ```TOML, or a bare ```).
    let after_open = trimmed.find('\n').map(|i| &trimmed[i + 1..])?;

    // The closing fence is the next line that begins with ```.
    let mut offset = 0usize;
    for line in after_open.split_inclusive('\n') {
        if line.trim_start().starts_with("```") {
            return Some((&after_open[..offset], &after_open[offset + line.len()..]));
        }
        offset += line.len();
    }
    // Unterminated fence — malformed, so decline rather than guess.
    None
}

/// The advisory title: the first `# ` ATX heading in the markdown body.
fn markdown_title(body: &str) -> Option<String> {
    body.lines()
        .map(str::trim)
        .find(|l| l.starts_with("# "))
        .map(|l| l.trim_start_matches("# ").trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Parse a RustSec advisory file (`.md` or `.toml`) into an [`Advisory`].
///
/// Reads `[advisory]` (id, package, optional cvss vector) and `[versions]`
/// (patched, unaffected). Informational advisories
/// (`[advisory].informational`, e.g. "unmaintained") are skipped — they are not
/// vulnerabilities. Severity is derived from the CVSS vector when present,
/// otherwise defaults to `Medium` (documented, conservative-ish).
///
/// The title is taken from the markdown body's first `# ` heading. Real RustSec
/// advisories carry no `title` field in their TOML — all 1,196 of them put it in
/// the prose — so reading only the TOML key yields an empty title on every real
/// advisory. The TOML key is still honoured when present, for bare-TOML files.
fn parse_rustsec_advisory(path: &Path) -> Option<Advisory> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let (toml_src, body) = split_advisory_frontmatter(&content)?;
    let val: toml::Value = toml::from_str(toml_src).ok()?;
    let adv = val.get("advisory")?;

    if adv.get("informational").is_some() {
        return None;
    }

    let id = adv.get("id")?.as_str()?.to_string();
    let package = adv.get("package")?.as_str()?.to_string();
    let title = adv
        .get("title")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| markdown_title(body))
        .unwrap_or_default();

    let cvss = adv
        .get("cvss")
        .and_then(|v| v.as_str())
        .and_then(cvss_base_score);
    let severity = cvss.map(Severity::from_score).unwrap_or(Severity::Medium);

    let versions = val.get("versions");
    let patched = versions
        .and_then(|v| v.get("patched"))
        .and_then(toml_str_array)
        .unwrap_or_default();
    let unaffected = versions
        .and_then(|v| v.get("unaffected"))
        .and_then(toml_str_array)
        .unwrap_or_default();

    Some(Advisory {
        id,
        ecosystem: Ecosystem::Cargo, // RustSec advisory-db is crates.io-only.
        package,
        title,
        severity,
        cvss,
        patched,
        unaffected,
    })
}

fn toml_str_array(v: &toml::Value) -> Option<Vec<String>> {
    v.as_array()
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
}

/// Map an OSV `ecosystem` string to our [`Ecosystem`]. Only the ecosystems we
/// scan are supported; anything else (Go, Maven, …) is skipped.
fn osv_ecosystem(s: &str) -> Option<Ecosystem> {
    // OSV may suffix a release name, e.g. "Debian:11"; match the leading token.
    let base = s.split(':').next().unwrap_or(s);
    if base.eq_ignore_ascii_case("crates.io") {
        Some(Ecosystem::Cargo)
    } else if base.eq_ignore_ascii_case("npm") {
        Some(Ecosystem::Npm)
    } else if base.eq_ignore_ascii_case("PyPI") {
        Some(Ecosystem::PyPI)
    } else {
        None
    }
}

/// Parse an OSV JSON file into zero or more advisories (one per affected
/// package in a supported ecosystem). Handles the common single semver range
/// shape:
/// `introduced` / `fixed` events become `>= introduced` (unaffected below) and
/// `>= fixed` (patched).
fn parse_osv_json(path: &Path) -> Vec<Advisory> {
    let content = match read_file_with_limit(path, MAX_MANIFEST_SIZE) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let val: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let id = val.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let title = val
        .get("summary")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("details").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    // Severity from a CVSS_V3 vector, when present.
    let cvss = val
        .get("severity")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|s| {
                let ty = s.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if ty.starts_with("CVSS_V3") {
                    s.get("score").and_then(|sc| sc.as_str()).and_then(cvss_base_score)
                } else {
                    None
                }
            })
        });
    let severity = cvss.map(Severity::from_score).unwrap_or(Severity::Medium);

    let mut out = Vec::new();
    let affected = match val.get("affected").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return out,
    };

    for aff in affected {
        let pkg = aff.get("package");
        let ecosystem = match pkg
            .and_then(|p| p.get("ecosystem"))
            .and_then(|e| e.as_str())
            .and_then(osv_ecosystem)
        {
            Some(e) => e,
            None => continue, // Unsupported ecosystem — skip this entry.
        };
        let raw_name = match pkg.and_then(|p| p.get("name")).and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        // PyPI advisory names are normalized (PEP 503) to match findings.
        let name = if ecosystem == Ecosystem::PyPI {
            crate::scanner::normalize_pypi_name(raw_name)
        } else {
            raw_name.to_string()
        };

        let mut patched = Vec::new();
        let mut unaffected = Vec::new();
        if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
            for range in ranges {
                if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                    for ev in events {
                        if let Some(introduced) = ev.get("introduced").and_then(|v| v.as_str()) {
                            if introduced != "0" && introduced != "0.0.0" {
                                unaffected.push(format!("< {}", introduced));
                            }
                        }
                        if let Some(fixed) = ev.get("fixed").and_then(|v| v.as_str()) {
                            patched.push(format!(">= {}", fixed));
                        }
                    }
                }
            }
        }

        out.push(Advisory {
            id: id.clone(),
            ecosystem,
            package: name,
            title: title.clone(),
            severity,
            cvss,
            patched,
            unaffected,
        });
    }
    out
}

/// Compute a CVSS v3.0/3.1 base score from a vector string, per the official
/// specification. Returns `None` if the vector is missing required base metrics.
///
/// A pure, deterministic transform (in the spirit of the project's other
/// testable converters) so severity is derived rather than hard-coded.
pub fn cvss_base_score(vector: &str) -> Option<f32> {
    let mut m: HashMap<&str, &str> = HashMap::new();
    for part in vector.split('/') {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k, v);
        }
    }
    // Require this to look like a CVSS v3 vector.
    if !m.get("CVSS").map(|v| v.starts_with("3.")).unwrap_or(false) {
        return None;
    }

    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.20,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let scope_changed = match *m.get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    // Privileges Required depends on Scope.
    let pr = match *m.get("PR")? {
        "N" => 0.85,
        "L" => {
            if scope_changed {
                0.68
            } else {
                0.62
            }
        }
        "H" => {
            if scope_changed {
                0.50
            } else {
                0.27
            }
        }
        _ => return None,
    };

    let impact_metric = |code: &str| -> Option<f64> {
        match m.get(code).copied()? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let c = impact_metric("C")?;
    let i = impact_metric("I")?;
    let a = impact_metric("A")?;

    let isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02).powf(15.0)
    } else {
        6.42 * isc_base
    };
    let exploitability = 8.22 * av * ac * pr * ui;

    let base = if impact <= 0.0 {
        0.0
    } else if scope_changed {
        roundup(f64::min(1.08 * (impact + exploitability), 10.0))
    } else {
        roundup(f64::min(impact + exploitability, 10.0))
    };
    Some(base as f32)
}

/// CVSS "Roundup": round up to one decimal place.
fn roundup(x: f64) -> f64 {
    (x * 10.0).ceil() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{CryptoType, Ecosystem, FindingType};

    fn advisory(pkg: &str, sev: Severity, patched: &[&str], unaffected: &[&str]) -> Advisory {
        advisory_in(Ecosystem::Cargo, pkg, sev, patched, unaffected)
    }

    fn advisory_in(
        ecosystem: Ecosystem,
        pkg: &str,
        sev: Severity,
        patched: &[&str],
        unaffected: &[&str],
    ) -> Advisory {
        Advisory {
            id: format!("TEST-{}", pkg),
            ecosystem,
            package: pkg.to_string(),
            title: "test advisory".to_string(),
            severity: sev,
            cvss: None,
            patched: patched.iter().map(|s| s.to_string()).collect(),
            unaffected: unaffected.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn locked_finding(name: &str, version: &str) -> CryptoFinding {
        locked_finding_in(Ecosystem::Cargo, name, version)
    }

    fn locked_finding_in(ecosystem: Ecosystem, name: &str, version: &str) -> CryptoFinding {
        CryptoFinding {
            path: "/p/manifest".to_string(),
            name: name.to_string(),
            finding_type: FindingType::TransitiveDependency,
            crypto_type: CryptoType::GeneralCrypto,
            ecosystem,
            version: Some(version.to_string()),
            version_source: VersionSource::Locked,
            details: String::new(),
        }
    }

    fn sv(version: &str) -> ParsedVersion {
        ParsedVersion::Semver(Version::parse(version).unwrap())
    }

    #[test]
    fn vulnerable_version_matches_patched_boundary() {
        let adv = advisory("foo", Severity::High, &[">= 1.2.0"], &[]);
        assert!(adv.affects(&sv("1.1.9")), "below fix is affected");
        assert!(!adv.affects(&sv("1.2.0")), "at fix is patched");
        assert!(!adv.affects(&sv("1.3.0")), "above fix is patched");
    }

    #[test]
    fn unaffected_range_excludes_old_versions() {
        // Introduced at 1.0.0, fixed at 1.2.0: only [1.0.0, 1.2.0) is affected.
        let adv = advisory("foo", Severity::Medium, &[">= 1.2.0"], &["< 1.0.0"]);
        assert!(!adv.affects(&sv("0.9.0")), "pre-introduction safe");
        assert!(adv.affects(&sv("1.1.0")), "in-window affected");
        assert!(!adv.affects(&sv("1.2.0")), "fixed safe");
    }

    #[test]
    fn correlate_skips_declared_and_dedups() {
        let mut db = AdvisoryDb::default();
        db.insert(advisory("foo", Severity::Critical, &[">= 2.0.0"], &[]));

        let mut declared = locked_finding("foo", "1.0.0");
        declared.version_source = VersionSource::Declared;
        let findings = vec![
            locked_finding("foo", "1.0.0"),
            locked_finding("foo", "1.0.0"), // duplicate, should dedup
            declared,                        // declared, should be skipped (counted)
            locked_finding("safe", "1.0.0"),
        ];

        let res = correlate(&db, &findings);
        assert_eq!(res.matches.len(), 1, "one vulnerable crate after dedup");
        assert_eq!(res.total_advisories(), 1);
        assert_eq!(res.worst_severity(), Some(Severity::Critical));
        assert_eq!(res.skipped_unresolved, 1, "declared version is skipped");
    }

    #[test]
    fn ecosystem_keying_prevents_cross_ecosystem_match() {
        // Same package name, vulnerable on npm only. A PyPI package of the same
        // name+version must not pick up the npm advisory, and vice versa.
        let mut db = AdvisoryDb::default();
        db.insert(advisory_in(Ecosystem::Npm, "shared", Severity::High, &[">= 2.0.0"], &[]));

        let findings = vec![
            locked_finding_in(Ecosystem::Npm, "shared", "1.0.0"),  // vulnerable
            locked_finding_in(Ecosystem::PyPI, "shared", "1.0.0"), // unrelated ecosystem
            locked_finding_in(Ecosystem::Cargo, "shared", "1.0.0"), // unrelated ecosystem
        ];

        let res = correlate(&db, &findings);
        assert_eq!(res.matches.len(), 1, "only the npm package matches");
        assert_eq!(res.matches[0].name, "shared");
        assert_eq!(res.worst_severity(), Some(Severity::High));

        // Direct lookups confirm the boundary.
        assert_eq!(db.matches(&Ecosystem::Npm, "shared", "1.0.0").len(), 1);
        assert!(db.matches(&Ecosystem::PyPI, "shared", "1.0.0").is_empty());
        assert!(db.matches(&Ecosystem::Cargo, "shared", "1.0.0").is_empty());
    }

    #[test]
    fn osv_ecosystem_maps_supported_only() {
        assert_eq!(osv_ecosystem("crates.io"), Some(Ecosystem::Cargo));
        assert_eq!(osv_ecosystem("npm"), Some(Ecosystem::Npm));
        assert_eq!(osv_ecosystem("PyPI"), Some(Ecosystem::PyPI));
        assert_eq!(osv_ecosystem("Debian:11"), None);
        assert_eq!(osv_ecosystem("Go"), None);
    }

    #[test]
    fn pypi_correlation_matches_normalized_name() {
        // An OSV PyPI advisory keyed by the canonical (normalized) name must
        // match a finding whose name is likewise normalized.
        let mut db = AdvisoryDb::default();
        db.insert(advisory_in(Ecosystem::PyPI, "pynacl", Severity::High, &[">= 1.5.0"], &[]));

        let findings = vec![locked_finding_in(Ecosystem::PyPI, "pynacl", "1.4.0")];
        let res = correlate(&db, &findings);
        assert_eq!(res.matches.len(), 1, "vulnerable PyPI package matches");
        assert_eq!(res.worst_severity(), Some(Severity::High));

        // A patched version is clean.
        let safe = vec![locked_finding_in(Ecosystem::PyPI, "pynacl", "1.5.0")];
        assert!(correlate(&db, &safe).matches.is_empty());
    }

    #[test]
    fn pypi_versions_compare_under_pep440() {
        // Two-component and pre-release PyPI versions are not valid semver and
        // used to be skipped entirely; they must now correlate.
        let mut db = AdvisoryDb::default();
        db.insert(advisory_in(
            Ecosystem::PyPI,
            "cryptography",
            Severity::High,
            &[">= 39.0.1"],
            &["< 1.8"],
        ));

        assert_eq!(
            db.matches(&Ecosystem::PyPI, "cryptography", "3.1").len(),
            1,
            "short release segment is affected"
        );
        assert_eq!(
            db.matches(&Ecosystem::PyPI, "cryptography", "39.0.1rc1").len(),
            1,
            "pre-release of the fix predates the fix"
        );
        assert!(
            db.matches(&Ecosystem::PyPI, "cryptography", "39.0.1").is_empty(),
            "fixed version is clean"
        );
        assert!(
            db.matches(&Ecosystem::PyPI, "cryptography", "1.7.2").is_empty(),
            "pre-introduction version is clean"
        );
        assert!(
            db.matches(&Ecosystem::PyPI, "cryptography", "not-a-version").is_empty(),
            "unparseable version matches nothing"
        );
    }

    #[test]
    fn version_scheme_is_ecosystem_dependent() {
        // "3.1" is a fine PEP 440 version but not semver: the same version
        // string correlates for PyPI yet still matches nothing for Cargo/npm.
        let mut db = AdvisoryDb::default();
        for eco in [Ecosystem::PyPI, Ecosystem::Cargo, Ecosystem::Npm] {
            db.insert(advisory_in(eco, "pkg", Severity::High, &[">= 4.0.0"], &[]));
        }
        assert_eq!(db.matches(&Ecosystem::PyPI, "pkg", "3.1").len(), 1);
        assert!(db.matches(&Ecosystem::Cargo, "pkg", "3.1").is_empty());
        assert!(db.matches(&Ecosystem::Npm, "pkg", "3.1").is_empty());
        // Full semver correlates everywhere.
        assert_eq!(db.matches(&Ecosystem::Cargo, "pkg", "3.1.0").len(), 1);
        assert_eq!(db.matches(&Ecosystem::Npm, "pkg", "3.1.0").len(), 1);
    }

    #[test]
    fn severity_ordering_supports_gating() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::None);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("moderate"), Some(Severity::Medium));
    }

    #[test]
    fn cvss_v31_known_vector_scores_correctly() {
        // CVE-2020-1472 (Zerologon) reference vector → 10.0 Critical.
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
        let score = cvss_base_score(v).expect("valid vector");
        assert!((score - 10.0).abs() < 0.05, "expected ~10.0, got {}", score);
        assert_eq!(Severity::from_score(score), Severity::Critical);

        // A low-impact vector should land well below Critical.
        let low = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N";
        let low_score = cvss_base_score(low).expect("valid vector");
        assert!(low_score < 4.0, "expected Low band, got {}", low_score);
    }

    #[test]
    fn non_cvss3_vector_returns_none() {
        assert!(cvss_base_score("not a vector").is_none());
        assert!(cvss_base_score("CVSS:2.0/AV:N/AC:L").is_none());
    }

    // --- Real-world RustSec `.md` format -----------------------------------
    //
    // These use the exact shape of files in the rustsec/advisory-db clone: a
    // fenced ```toml block, then prose whose first `# ` heading is the title.
    // The previous fixtures were all hand-written bare TOML, which is why the
    // loader could accept zero real advisories with every test still green.

    /// Verbatim structure of `crates/actix-http/RUSTSEC-2020-0048.md`.
    const REAL_ADVISORY_MD: &str = r#"```toml
[advisory]
id = "RUSTSEC-2020-0048"
package = "actix-http"
aliases = ["CVE-2020-35901", "GHSA-v3j6-xf77-8r9c"]
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
categories = ["memory-corruption"]
date = "2020-01-24"
url = "https://github.com/actix/actix-web/issues/1321"

[versions]
patched = [">= 2.0.0-alpha.1"]
```

# Use-after-free in BodyStream due to lack of pinning

Affected versions of this crate did not require the buffer wrapped in
`BodyStream` to be pinned.
"#;

    fn write_tmp(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lens3329-adv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_real_rustsec_markdown_advisory() {
        let path = write_tmp("RUSTSEC-2020-0048.md", REAL_ADVISORY_MD);
        let adv = parse_rustsec_advisory(&path).expect("real .md advisory should parse");

        assert_eq!(adv.id, "RUSTSEC-2020-0048");
        assert_eq!(adv.package, "actix-http");
        assert_eq!(adv.ecosystem, Ecosystem::Cargo);
        // Title lives in the prose, not the TOML.
        assert_eq!(adv.title, "Use-after-free in BodyStream due to lack of pinning");
        assert_eq!(adv.patched, vec![">= 2.0.0-alpha.1".to_string()]);
        // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H => 7.5 High.
        assert_eq!(adv.severity, Severity::High);
        assert!((adv.cvss.unwrap() - 7.5).abs() < 0.05);
    }

    #[test]
    fn real_markdown_advisory_correlates_against_a_locked_finding() {
        let path = write_tmp("RUSTSEC-2020-0048-corr.md", REAL_ADVISORY_MD);
        let mut db = AdvisoryDb::default();
        db.insert(parse_rustsec_advisory(&path).unwrap());

        let vulnerable = locked_finding("actix-http", "1.0.0");
        assert_eq!(db.matches(&Ecosystem::Cargo, "actix-http", "1.0.0").len(), 1);
        assert!(!correlate(&db, std::slice::from_ref(&vulnerable)).matches.is_empty());

        // Patched version must not match.
        assert!(db.matches(&Ecosystem::Cargo, "actix-http", "2.0.0").is_empty());
    }

    #[test]
    fn informational_markdown_advisory_is_skipped() {
        // `informational = "unmaintained"` — 476 of the 1,196 real advisories.
        let path = write_tmp(
            "RUSTSEC-2025-0123.md",
            "```toml\n[advisory]\nid = \"RUSTSEC-2025-0123\"\npackage = \"opentelemetry-jaeger\"\n\
             informational = \"unmaintained\"\n\n[versions]\npatched = []\n```\n\n# unmaintained\n",
        );
        assert!(parse_rustsec_advisory(&path).is_none());
    }

    #[test]
    fn non_advisory_markdown_is_skipped() {
        // The repo's README / contributor guides have no leading TOML block.
        let path = write_tmp("README.md", "# RustSec Advisory Database\n\nProse only.\n");
        assert!(parse_rustsec_advisory(&path).is_none());
    }

    #[test]
    fn bare_toml_advisory_still_parses() {
        // Regression guard: the hand-written fixture shape must keep working.
        let path = write_tmp(
            "bare.toml",
            "[advisory]\nid = \"RUSTSEC-2099-0001\"\npackage = \"ring\"\n\
             title = \"Explicit title\"\n\n[versions]\npatched = [\">= 0.18.0\"]\n",
        );
        let adv = parse_rustsec_advisory(&path).expect("bare TOML should still parse");
        assert_eq!(adv.package, "ring");
        assert_eq!(adv.title, "Explicit title");
    }

    #[test]
    fn unterminated_fence_is_declined() {
        assert!(split_advisory_frontmatter("```toml\n[advisory]\nid = \"x\"\n").is_none());
    }

    #[test]
    fn empty_db_is_reported_as_empty() {
        // What the CLI's fail-loud guard keys off.
        assert!(AdvisoryDb::default().is_empty());
        assert_eq!(AdvisoryDb::default().len(), 0);
    }
}
