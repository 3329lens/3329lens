# lens3329

Cryptographic inventory scanning as a library: crypto-dependency discovery,
lockfile version resolution, offline advisory/CVE correlation, and CycloneDX
CBOM / SARIF export.

This is the engine behind **3329lens**, a continuous cryptographic inventory and
post-quantum-readiness tool.

## Crate name vs. command name

The crate is published as **`lens3329`**; the product, the CLI binary, the
domain and the GitHub org are all **`3329lens`**.

The reason is mundane: Cargo rejects package names that start with a digit, so
`3329lens` is not a registrable crate name. The digits are transposed for the
registry only. If you are looking for the command-line tool, you want
`3329lens`; if you are embedding the scanner in your own Rust program, you want
`lens3329`:

```toml
[dependencies]
lens3329 = "0.1"
```

(The name `3329` is the modulus *q* of ML-KEM/Kyber.)

## What it does

- **Discovery** — walks a filesystem tree and identifies cryptographic
  libraries: binary artifacts (`.so`, `.dll`, `.dylib`, `.a`) and declared
  dependencies in `Cargo.toml`, `package.json`, `requirements.txt`,
  `pyproject.toml` (Poetry and PEP 621) and `Pipfile`. Findings are categorized
  by crypto type (SSL/TLS, general crypto, post-quantum, hash functions, …).
- **Lockfile resolution** — when a lockfile sits beside a scanned manifest
  (`Cargo.lock`, `package-lock.json` / `npm-shrinkwrap.json`, `poetry.lock`,
  `Pipfile.lock`), declared version ranges are replaced with the resolved
  version (`VersionSource::Locked`) and crypto packages pulled in
  *transitively* are surfaced as well. Accurate versions are what make purls
  and CVE correlation meaningful.
- **Advisory correlation** — matches resolved versions against a *local*
  advisory database: a RustSec `advisory-db` clone (`.md` advisories with a
  fenced TOML block, or bare `.toml`) and/or an OSV JSON export. No network
  access. A database that yields zero usable advisories is a hard error rather
  than a silent "nothing matched", so `--fail-on` cannot pass for the wrong
  reason. Advisories are indexed by `(ecosystem, name)`, so
  same-named packages on crates.io, npm and PyPI cannot cross-match. Version
  comparison is ecosystem-aware — semver for Cargo and npm, a from-scratch
  PEP 440 comparator for PyPI. Severity is derived by computing CVSS v3.x base
  scores from advisory vectors.
- **CycloneDX 1.6 CBOM export** — `library` and `cryptographic-asset`
  components, library→algorithm dependency links, synthesized purls, quantum
  risk flagged via `nistQuantumSecurityLevel`, and a `vulnerabilities[]` array
  when an advisory DB is supplied.
- **SARIF 2.1.0 export** — correlated vulnerabilities as SARIF results so they
  render natively in code-scanning UIs (GitHub/GitLab code scanning, the VS Code
  SARIF Viewer, SAST dashboards).

The crate is deliberately UI-free and depends only on `serde`, `serde_json`,
`toml`, `regex`, `semver`, `walkdir` and `chrono`.

## Usage

```rust
use lens3329::scanner::CryptoScanner;
use lens3329::{advisories, cbom, sarif};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut scanner = CryptoScanner::new();
    scanner.scan("/path/to/project", Some(5))?;
    let findings = scanner.get_findings();

    // CycloneDX 1.6 CBOM
    let bom = cbom::findings_to_cbom(findings, "/path/to/project");
    println!("{}", serde_json::to_string_pretty(&bom)?);

    // Offline advisory correlation + SARIF
    let db = advisories::AdvisoryDb::load_from_dir(Path::new("/path/to/advisory-db"))?;
    let correlation = advisories::correlate(&db, findings);
    let log = sarif::build(&correlation, "/path/to/project");
    println!("{}", serde_json::to_string_pretty(&log)?);

    Ok(())
}
```

`CryptoScanner::scan_streaming` emits `StreamingScanEvent`s over a channel if
you want progress as the walk proceeds rather than a batch result.

## Modules

| Module | Responsibility |
| --- | --- |
| `scanner` | Filesystem walk, binary and manifest detection, `CryptoFinding` model |
| `lockfile` | `Cargo.lock`, npm, Poetry and Pipenv lockfile parsing → resolved versions |
| `advisories` | Advisory DB loading (RustSec/OSV), version matching, CVSS v3 scoring |
| `pep440` | PEP 440 version parsing and total ordering, for PyPI comparisons |
| `cbom` | CycloneDX 1.6 CBOM construction |
| `sarif` | SARIF 2.1.0 log construction |
| `library` | Shared scan-result types (`LibraryInfo`, `LibraryCategory`, `RiskLevel`) |

## Scope and limitations

Please read this before relying on the output:

- **Algorithm assets in the CBOM are inferred from library identity, not from
  observed runtime calls.** An algorithm component means "this library can do
  X", not "X is actually invoked". Versions and transitive dependencies, by
  contrast, are evidence-based (lockfile-resolved).
- **Only lockfile-resolved versions are correlated against advisories.**
  Declared-only version ranges are skipped rather than guessed, and a version
  that fails its ecosystem's parser matches nothing rather than being assumed
  vulnerable.
- Advisory coverage is limited to the local database you supply, and to the
  Cargo, npm and PyPI ecosystems. This is not a replacement for `cargo audit`,
  `npm audit` or `pip-audit`.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
