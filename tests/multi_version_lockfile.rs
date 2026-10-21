//! Regression tests for lockfiles that hold several versions of one package.
//!
//! Up to 0.2.1 every lockfile parser kept only the first version of each
//! package name, so any other version was never correlated against advisories.
//! A `Cargo.lock` holding both rustls 0.21 and 0.23 would report only 0.21,
//! and an advisory affecting only 0.23 matched nothing. These tests drive the
//! public scanner and correlation APIs end to end, through both the batch and
//! the streaming scan.

use std::path::{Path, PathBuf};

use lens3329::advisories::{self, AdvisoryDb};
use lens3329::scanner::{CryptoFinding, CryptoScanner, FindingType, VersionSource};

/// A fresh, empty directory unique to this test process and `tag`.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lens3329_multi_version_{}_{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, contents: &str) {
    std::fs::write(dir.join(name), contents).unwrap();
}

const CARGO_LOCK: &str = r#"
version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["rustls 0.21.12"]

[[package]]
name = "rustls"
version = "0.21.12"

[[package]]
name = "rustls"
version = "0.23.35"
"#;

/// A RustSec advisory, in the database's own format, that affects 0.23.35 but
/// not 0.21.12. Under the old first-version-only parser it matched nothing.
const ADVISORY_ONLY_023: &str = r#"```toml
[advisory]
id = "RUSTSEC-0000-0001"
package = "rustls"
date = "2026-10-14"
url = "https://example.invalid/advisory"
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

[versions]
patched = [">= 0.23.46"]
unaffected = ["< 0.23.0"]
```

# Test advisory affecting only rustls 0.23
"#;

/// A Cargo project declaring rustls 0.21 directly, with 0.23 also locked.
fn cargo_project(tag: &str) -> PathBuf {
    let dir = temp_dir(tag);
    write(
        &dir,
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nrustls = \"0.21\"\n",
    );
    write(&dir, "Cargo.lock", CARGO_LOCK);
    dir
}

fn advisory_db(tag: &str) -> (PathBuf, AdvisoryDb) {
    let dir = temp_dir(tag);
    let crate_dir = dir.join("crates").join("rustls");
    std::fs::create_dir_all(&crate_dir).unwrap();
    write(&crate_dir, "RUSTSEC-0000-0001.md", ADVISORY_ONLY_023);
    let db = AdvisoryDb::load_from_dir(&dir).unwrap();
    assert!(!db.is_empty(), "the test advisory must load");
    (dir, db)
}

fn rustls_findings(findings: &[CryptoFinding]) -> Vec<(String, FindingType)> {
    let mut out: Vec<_> = findings
        .iter()
        .filter(|f| f.name == "rustls")
        .map(|f| {
            assert_eq!(f.version_source, VersionSource::Locked);
            (f.version.clone().unwrap(), f.finding_type.clone())
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn every_locked_version_becomes_a_finding() {
    let dir = cargo_project("batch");
    let mut scanner = CryptoScanner::new();
    scanner.scan(dir.to_str().unwrap(), None).unwrap();

    // The declared requirement "0.21" picks the direct one; 0.23 is reported
    // as transitive rather than dropped.
    assert_eq!(
        rustls_findings(scanner.get_findings()),
        [
            ("0.21.12".to_string(), FindingType::DependencyManifest),
            ("0.23.35".to_string(), FindingType::TransitiveDependency),
        ]
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn advisory_affecting_only_the_second_version_matches() {
    let dir = cargo_project("correlate");
    let (db_dir, db) = advisory_db("correlate_db");

    let mut scanner = CryptoScanner::new();
    scanner.scan(dir.to_str().unwrap(), None).unwrap();
    let result = advisories::correlate(&db, scanner.get_findings());

    let matched: Vec<(&str, &str)> = result
        .matches
        .iter()
        .map(|m| (m.name.as_str(), m.version.as_str()))
        .collect();
    assert_eq!(matched, [("rustls", "0.23.35")]);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&db_dir).ok();
}

#[test]
fn streaming_scan_reports_the_same_findings_as_batch() {
    let dir = cargo_project("streaming");

    let mut batch = CryptoScanner::new();
    batch.scan(dir.to_str().unwrap(), None).unwrap();

    let mut streaming = CryptoScanner::new();
    streaming
        .scan_streaming(dir.to_str().unwrap(), None, |_| {})
        .unwrap();

    assert_eq!(
        rustls_findings(batch.get_findings()),
        rustls_findings(streaming.get_findings())
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn npm_direct_finding_uses_the_top_level_copy() {
    // The nested copy sorts before the top-level one in the lockfile, so the
    // old "first occurrence" rule reported the version the project does not
    // import as its direct dependency.
    let dir = temp_dir("npm");
    write(
        &dir,
        "package.json",
        r#"{ "name": "demo", "dependencies": { "node-forge": "^1.3.1" } }"#,
    );
    write(
        &dir,
        "package-lock.json",
        r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo" },
    "node_modules/a-dep/node_modules/node-forge": { "version": "0.10.0" },
    "node_modules/node-forge": { "version": "1.3.1" }
  }
}"#,
    );

    let mut scanner = CryptoScanner::new();
    scanner.scan(dir.to_str().unwrap(), None).unwrap();
    let mut forge: Vec<_> = scanner
        .get_findings()
        .iter()
        .filter(|f| f.name == "node-forge")
        .map(|f| (f.version.clone().unwrap(), f.finding_type.clone()))
        .collect();
    forge.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        forge,
        [
            ("0.10.0".to_string(), FindingType::TransitiveDependency),
            ("1.3.1".to_string(), FindingType::DependencyManifest),
        ]
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The CI gate itself: before the fix, `--fail-on` exited 0 here because the
/// affected version was never checked.
#[cfg(feature = "cli")]
#[test]
fn fail_on_trips_for_an_advisory_on_the_second_version() {
    let dir = cargo_project("cli");
    let (db_dir, _db) = advisory_db("cli_db");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_3329lens"))
        .args(["scan", "--path"])
        .arg(&dir)
        .arg("--advisory-db")
        .arg(&db_dir)
        .args(["--fail-on", "high"])
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(2),
        "a matched critical advisory must exit 2"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&db_dir).ok();
}
