//! Differential test against a real OSV corpus.
//!
//! The unit tests in `advisories.rs` use fixtures written by hand, which is
//! exactly how the advisory loader shipped for months while silently matching
//! nothing real. This test instead runs the public correlation path over an
//! actual OSV export and compares every verdict against expectations produced
//! by an independent implementation of the OSV range semantics.
//!
//! It is skipped unless both environment variables are set, because the corpus
//! is hundreds of megabytes and cannot live in the repository:
//!
//! ```text
//! curl -O https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip
//! unzip -q all.zip -d /tmp/osv-crates
//! python3 scripts/gen_osv_cases.py /tmp/osv-crates /tmp/osv-cases.json
//! LENS3329_OSV_CORPUS=/tmp/osv-crates \
//! LENS3329_OSV_CASES=/tmp/osv-cases.json \
//!   cargo test --test osv_corpus -- --nocapture
//! ```
//!
//! `tests/fixtures/osv/` holds a small vendored subset of the same corpus so the
//! shapes this test discovered stay covered by `cargo test` alone.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lens3329::advisories::AdvisoryDb;
use lens3329::scanner::Ecosystem;

#[derive(serde::Deserialize)]
struct Case {
    advisory: String,
    ecosystem: String,
    package: String,
    version: String,
    expected: bool,
}

#[test]
fn osv_corpus_matches_independent_reference() {
    let (corpus, cases) = match (
        std::env::var("LENS3329_OSV_CORPUS"),
        std::env::var("LENS3329_OSV_CASES"),
    ) {
        (Ok(c), Ok(k)) => (PathBuf::from(c), PathBuf::from(k)),
        _ => {
            eprintln!("skipping: set LENS3329_OSV_CORPUS and LENS3329_OSV_CASES to run");
            return;
        }
    };

    let db = AdvisoryDb::load_from_dir(&corpus).expect("corpus loads");
    assert!(!db.is_empty(), "corpus loaded no advisories");
    eprintln!("loaded {} advisories from {}", db.len(), corpus.display());

    let raw = std::fs::read_to_string(&cases).expect("cases file readable");
    let cases: Vec<Case> = serde_json::from_str(&raw).expect("cases parse");
    eprintln!("checking {} cases", cases.len());

    // Group mismatches by advisory so a systematic shape failure shows up as one
    // cluster rather than thousands of individual lines.
    let mut false_neg: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut false_pos: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for c in &cases {
        let eco = match c.ecosystem.split(':').next().unwrap_or("") {
            "crates.io" => Ecosystem::Cargo,
            "npm" => Ecosystem::Npm,
            "PyPI" => Ecosystem::PyPI,
            other => panic!("unexpected ecosystem in cases file: {other}"),
        };
        let matched = db
            .matches(&eco, &c.package, &c.version)
            .iter()
            .any(|a| a.id == c.advisory);
        if matched != c.expected {
            let entry = format!("{}@{}", c.package, c.version);
            if c.expected {
                false_neg.entry(c.advisory.clone()).or_default().push(entry);
            } else {
                false_pos.entry(c.advisory.clone()).or_default().push(entry);
            }
        }
    }

    let report = |label: &str, m: &BTreeMap<String, Vec<String>>| {
        let total: usize = m.values().map(|v| v.len()).sum();
        eprintln!("\n{label}: {total} across {} advisories", m.len());
        for (adv, vs) in m.iter().take(15) {
            let shown: Vec<_> = vs.iter().take(4).cloned().collect();
            let more = if vs.len() > 4 {
                format!(" (+{} more)", vs.len() - 4)
            } else {
                String::new()
            };
            eprintln!("  {adv}: {}{more}", shown.join(", "));
        }
        total
    };

    let fneg = report("FALSE NEGATIVES (vulnerable, not reported)", &false_neg);
    let fpos = report("FALSE POSITIVES (clean, reported vulnerable)", &false_pos);

    assert_eq!(
        (fneg, fpos),
        (0, 0),
        "corpus differential found {fneg} false negatives and {fpos} false positives \
         across {} cases",
        cases.len()
    );
}
