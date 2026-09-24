//! SARIF 2.1.0 output for correlated vulnerabilities.
//!
//! Emits a Static Analysis Results Interchange Format log so that the CVEs
//! Slow Lynx correlates (from a lockfile-resolved scan against an offline
//! advisory DB) surface natively in GitHub / GitLab code scanning, the VS Code
//! SARIF Viewer, and most SAST dashboards.
//!
//! Scope (v1): **vulnerabilities only**. Each matched advisory becomes one
//! SARIF `result`; unique advisory IDs are deduplicated into `rules`. Crypto
//! inventory findings are not emitted — they are inventory, not defects.
//!
//! The structs are a hand-rolled subset of the spec (mirroring how `cbom.rs`
//! hand-rolls CycloneDX) to avoid pulling in a SARIF crate. Teaching-grade.

use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

use crate::advisories::{CorrelationResult, Severity};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const TOOL_NAME: &str = "slow-lynx";
const TOOL_INFO_URI: &str = "https://gitlab.com/lomyen/slow_lynx_cryptography_discovery";

#[derive(Debug, Serialize)]
pub struct SarifLog {
    pub version: &'static str,
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub driver: ToolComponent,
}

#[derive(Debug, Serialize)]
pub struct ToolComponent {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<ReportingDescriptor>,
}

#[derive(Debug, Serialize)]
pub struct ReportingDescriptor {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: Message,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: Configuration,
    pub properties: RuleProperties,
}

#[derive(Debug, Serialize)]
pub struct Configuration {
    pub level: String,
}

#[derive(Debug, Serialize, Default)]
pub struct RuleProperties {
    /// GitHub code scanning reads this (a CVSS-style string) to bucket severity.
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: Message,
    pub locations: Vec<Location>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct Message {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Debug, Serialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: u32,
}

/// Map a qualitative [`Severity`] to a SARIF result `level`.
fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None => "note",
    }
}

/// Make `path` relative to the scan `root` so code-scanning UIs map results to
/// repository files. Falls back to the original path if it isn't under `root`.
fn relativize(path: &str, root: &str) -> String {
    let p = Path::new(path);
    let r = Path::new(root);
    match p.strip_prefix(r) {
        Ok(rel) => {
            let s = rel.to_string_lossy().to_string();
            if s.is_empty() {
                ".".to_string()
            } else {
                s
            }
        }
        Err(_) => path.to_string(),
    }
}

/// Build a SARIF 2.1.0 log from correlated vulnerabilities.
///
/// `root` is the canonicalized scan root used to relativize result locations.
/// An empty `correlation` (e.g. no `--advisory-db` supplied) yields a valid
/// run with empty `rules`/`results`.
pub fn build(correlation: &CorrelationResult, root: &str) -> SarifLog {
    // Deduplicate advisories into rules by id, preserving first-seen order.
    let mut rules: Vec<ReportingDescriptor> = Vec::new();
    let mut rule_index: HashMap<String, ()> = HashMap::new();
    let mut results: Vec<SarifResult> = Vec::new();

    for m in &correlation.matches {
        let uri = relativize(&m.path, root);
        for adv in &m.advisories {
            if rule_index.insert(adv.id.clone(), ()).is_none() {
                rules.push(ReportingDescriptor {
                    id: adv.id.clone(),
                    name: adv.id.clone(),
                    short_description: Message {
                        text: if adv.title.is_empty() {
                            adv.id.clone()
                        } else {
                            adv.title.clone()
                        },
                    },
                    help_uri: advisory_help_uri(&adv.id),
                    default_configuration: Configuration {
                        level: severity_to_level(adv.severity).to_string(),
                    },
                    properties: RuleProperties {
                        security_severity: adv.cvss.map(|s| format!("{:.1}", s)),
                    },
                });
            }

            let mut fingerprints = HashMap::new();
            fingerprints.insert(
                "slowLynx/v1".to_string(),
                format!("{}:{}:{}", adv.id, m.name, m.version),
            );

            results.push(SarifResult {
                rule_id: adv.id.clone(),
                level: severity_to_level(adv.severity).to_string(),
                message: Message {
                    text: format!(
                        "{}@{}: {} ({}, {})",
                        m.name,
                        m.version,
                        if adv.title.is_empty() {
                            adv.id.as_str()
                        } else {
                            adv.title.as_str()
                        },
                        adv.id,
                        adv.severity.as_str()
                    ),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation { uri: uri.clone() },
                        // Manifests carry no per-line attribution today; point at
                        // the file head so UIs still anchor the result.
                        region: Region { start_line: 1 },
                    },
                }],
                partial_fingerprints: fingerprints,
            });
        }
    }

    SarifLog {
        version: SARIF_VERSION,
        schema: SARIF_SCHEMA,
        runs: vec![Run {
            tool: Tool {
                driver: ToolComponent {
                    name: TOOL_NAME.to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: TOOL_INFO_URI.to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

/// Best-effort canonical advisory URL for the common ID schemes.
fn advisory_help_uri(id: &str) -> Option<String> {
    if id.starts_with("RUSTSEC-") {
        Some(format!("https://rustsec.org/advisories/{}.html", id))
    } else if id.starts_with("CVE-") {
        Some(format!("https://nvd.nist.gov/vuln/detail/{}", id))
    } else if id.starts_with("GHSA-") {
        Some(format!("https://github.com/advisories/{}", id))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisories::{Advisory, CorrelationResult, FindingMatch, Severity};

    fn advisory(id: &str, severity: Severity, cvss: Option<f32>) -> Advisory {
        Advisory::for_test(id, severity, cvss, "Example title")
    }

    fn result_with(matches: Vec<FindingMatch>) -> CorrelationResult {
        CorrelationResult {
            matches,
            skipped_unresolved: 0,
        }
    }

    #[test]
    fn severity_maps_to_sarif_level() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
        assert_eq!(severity_to_level(Severity::High), "error");
        assert_eq!(severity_to_level(Severity::Medium), "warning");
        assert_eq!(severity_to_level(Severity::Low), "note");
        assert_eq!(severity_to_level(Severity::None), "note");
    }

    #[test]
    fn cvss_emitted_as_security_severity_property() {
        let corr = result_with(vec![FindingMatch {
            name: "pynacl".into(),
            version: "1.4.0".into(),
            path: "/scan/requirements.txt".into(),
            advisories: vec![advisory("CVE-2020-0001", Severity::Critical, Some(9.8))],
        }]);
        let log = build(&corr, "/scan");
        let rule = &log.runs[0].tool.driver.rules[0];
        assert_eq!(rule.properties.security_severity.as_deref(), Some("9.8"));
    }

    #[test]
    fn one_rule_per_advisory_id_deduplicated() {
        // Same CVE affects two different packages → 1 rule, 2 results.
        let shared = advisory("CVE-2021-9999", Severity::High, Some(7.5));
        let corr = result_with(vec![
            FindingMatch {
                name: "pkg-a".into(),
                version: "1.0.0".into(),
                path: "/scan/a/Cargo.toml".into(),
                advisories: vec![shared.clone()],
            },
            FindingMatch {
                name: "pkg-b".into(),
                version: "2.0.0".into(),
                path: "/scan/b/Cargo.toml".into(),
                advisories: vec![shared],
            },
        ]);
        let log = build(&corr, "/scan");
        assert_eq!(log.runs[0].tool.driver.rules.len(), 1);
        assert_eq!(log.runs[0].results.len(), 2);
    }

    #[test]
    fn result_location_uri_is_relative_to_scan_root() {
        let corr = result_with(vec![FindingMatch {
            name: "node-forge".into(),
            version: "1.0.0".into(),
            path: "/scan/app/package.json".into(),
            advisories: vec![advisory("GHSA-xxxx", Severity::Medium, Some(5.0))],
        }]);
        let log = build(&corr, "/scan");
        let uri = &log.runs[0].results[0].locations[0]
            .physical_location
            .artifact_location
            .uri;
        assert_eq!(uri, "app/package.json");
    }

    #[test]
    fn empty_correlation_produces_valid_empty_run() {
        let log = build(&CorrelationResult::default(), "/scan");
        assert_eq!(log.runs.len(), 1);
        assert!(log.runs[0].results.is_empty());
        assert!(log.runs[0].tool.driver.rules.is_empty());
    }

    #[test]
    fn serialized_log_has_version_and_schema() {
        let log = build(&CorrelationResult::default(), "/scan");
        let json = serde_json::to_string(&log).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "slow-lynx");
    }

    #[test]
    fn help_uri_derived_for_known_id_schemes() {
        assert!(advisory_help_uri("RUSTSEC-2021-0001")
            .unwrap()
            .contains("rustsec.org"));
        assert!(advisory_help_uri("CVE-2020-0001")
            .unwrap()
            .contains("nvd.nist.gov"));
        assert!(advisory_help_uri("GHSA-aaaa-bbbb-cccc")
            .unwrap()
            .contains("github.com/advisories"));
        assert!(advisory_help_uri("UNKNOWN-1").is_none());
    }
}
