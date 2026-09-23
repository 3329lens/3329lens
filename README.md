# 3329lens

Cryptographic inventory scanner. It walks a codebase, finds the cryptography it
depends on, resolves real versions from lockfiles, correlates those against an
offline advisory database, and exports the result as a CycloneDX CBOM or a
SARIF log.

It answers two questions that are hard to answer by reading a dependency tree:
**what cryptography is actually in here**, and **which of it breaks when a
cryptographically relevant quantum computer arrives**.

Everything runs offline. The scanner makes no network requests.

## Install

```bash
cargo install lens3329      # installs the `3329lens` binary
3329lens --help
```

Pre-1.0. See [SECURITY.md](SECURITY.md) for the support and disclosure policy.

## Quick start

```bash
# Human-readable inventory of the current directory
3329lens scan

# Scan a specific tree, limit the walk depth
3329lens scan --path ./my-project --depth 5

# Machine-readable
3329lens scan --path . --format json --output inventory.json
```

Four output formats: `text` (default), `json`, `cbom` (CycloneDX 1.6) and
`sarif` (SARIF 2.1.0).

### Correlating against advisories

Correlation needs a local advisory database — a clone of the RustSec
`advisory-db`, an OSV JSON export, or both:

```bash
git clone --depth 1 https://github.com/rustsec/advisory-db

3329lens scan --path . --advisory-db ./advisory-db
```

Only **lockfile-resolved** versions are correlated. A declared range such as
`^1.2` is skipped rather than guessed, because guessing produces either false
alarms or false comfort.

If the database you point at yields no usable advisories, that is a **hard
error**, not an empty result. A scan reporting "nothing matched" because
nothing *loaded* is indistinguishable from a clean bill of health, and would
make the CI gate below pass for the wrong reason.

### Gating CI

```bash
3329lens scan --path . --advisory-db ./advisory-db --fail-on high
```

| Exit code | Meaning |
| --- | --- |
| `0` | Success — no finding met the `--fail-on` threshold |
| `1` | Operational error (bad path, unreadable database, write failure) |
| `2` | A vulnerability at or above the threshold was found |

Thresholds: `none` (default), `low`, `medium`, `high`, `critical`. The two
failure codes are kept distinct on purpose — a broken scan and a failing scan
are different problems and should not share an exit status.

### GitHub code scanning

```yaml
- run: 3329lens scan --path . --advisory-db ./advisory-db --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Each matched advisory becomes one SARIF result; advisory IDs become rules;
severity maps to `level`, and the CVSS base score is written to
`properties["security-severity"]`, which is what GitHub reads to bucket
severity. Results anchor to the originating manifest or lockfile.

### CycloneDX CBOM

```bash
3329lens scan --path . --depth 5 --format cbom --advisory-db ./advisory-db --output cbom.json
```

The CBOM carries `library` and `cryptographic-asset` components,
library→algorithm dependency links, synthesized purls (`pkg:cargo/…`,
`pkg:npm/…` with scoped-name encoding, `pkg:pypi/…`), quantum risk flagged via
`nistQuantumSecurityLevel` (`0` = breakable by Shor's algorithm), and a
`vulnerabilities[]` array when an advisory database is supplied.

## Interactive dashboard

```bash
3329lens scanner-dashboard --path ./my-project --depth 5
```

A terminal UI that populates as the scan proceeds, rather than making you wait
for a report. Four views:

| | View | Shows |
| --- | --- | --- |
| `1` | **Live Scan** | Discoveries as they happen, progress, file and directory counts, scan rate |
| `2` | **Category** | Collapsible groups by crypto type, with versions, risk and detail |
| `3` | **Statistics** | Category and quantum-risk distribution as bar charts |
| `4` | **Migration** | Prioritised post-quantum migration plan with status tracking |

| Key | Action |
| --- | --- |
| `Tab` / `1`–`4` | Cycle views / jump to a view |
| `↑` `↓` or `k` `j` | Move the selection |
| `Home`/`g`, `End`/`G` | Jump to first / last |
| `Enter` or `d` | Open the detail view for the selected library |
| `a` / `c` | Expand / collapse all categories (Category view) |
| `f` / `x` | Filter to quantum-vulnerable only / clear filters |
| `s` | Cycle sort: name, category, risk, size, date |
| `m` | Toggle migration status (Migration view) |
| `e` | Export — JSON, or the migration plan as Markdown in the Migration view |
| `v` | Export the inventory as CSV |
| `Space` | Pause / resume |
| `h` or `F1` | Help overlay |
| `q` / `Esc` | Quit |

Exports are written to timestamped files in the working directory.

## What it detects

- **Binary artifacts** — `.so`, `.dll`, `.dylib`, `.a`.
- **Declared dependencies** — `Cargo.toml`, `package.json`,
  `requirements.txt`, `pyproject.toml` (Poetry and PEP 621), `Pipfile`.
- **Resolved versions and transitive crypto** — when a lockfile sits beside a
  manifest (`Cargo.lock`, `package-lock.json` / `npm-shrinkwrap.json`,
  `poetry.lock`, `Pipfile.lock`), declared ranges are replaced with the
  resolved version and crypto pulled in *transitively* is surfaced too. This is
  what makes purls and CVE correlation meaningful rather than decorative.

Findings are categorised by crypto type — SSL/TLS, general crypto,
post-quantum, hash functions, and language-ecosystem groupings — and flagged
for quantum risk.

Version comparison is ecosystem-aware: semver for Cargo and npm, a from-scratch
PEP 440 comparator for PyPI, so Python pre/post/dev releases, epochs and short
versions like `3.1` compare correctly. Advisories are indexed by
`(ecosystem, name)`, so same-named packages on crates.io, npm and PyPI cannot
cross-match.

## Crate name vs. command name

The crate is published as **`lens3329`**; the product, the CLI binary, the
domain and the GitHub org are all **`3329lens`**.

The reason is mundane: Cargo rejects package names that start with a digit, so
`3329lens` is not a registrable crate name. The digits are transposed for the
registry only. If you are looking for the command-line tool, you want
`3329lens`; if you are embedding the scanner in your own Rust program, you want
`lens3329`.

(The name `3329` is the modulus *q* of ML-KEM/Kyber.)

## Using it as a library

The scanning and correlation core is usable on its own, with no UI dependencies:

```toml
[dependencies]
lens3329 = { version = "0.1", default-features = false }
```

```rust
use lens3329::scanner::CryptoScanner;
use lens3329::{advisories, cbom, sarif};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut scanner = CryptoScanner::new();
    scanner.scan("./my-project", Some(5))?;
    let findings = scanner.get_findings();

    // CycloneDX 1.6 CBOM
    let bom = cbom::findings_to_cbom(findings, "./my-project");
    println!("{}", serde_json::to_string_pretty(&bom)?);

    // Offline advisory correlation + SARIF
    let db = advisories::AdvisoryDb::load_from_dir(Path::new("./advisory-db"))?;
    let correlation = advisories::correlate(&db, findings);
    let log = sarif::build(&correlation, "./my-project");
    println!("{}", serde_json::to_string_pretty(&log)?);

    Ok(())
}
```

`CryptoScanner::scan_streaming` emits `StreamingScanEvent`s over a channel if
you want progress as the walk proceeds rather than a batch result.

Without `default-features = false` you also get the CLI and TUI stack (`clap`,
`colored`, `crossterm`, `ratatui`). The lean core depends only on `serde`,
`serde_json`, `toml`, `regex`, `semver`, `walkdir`, `chrono` and `getrandom`.

| Module | Responsibility |
| --- | --- |
| `scanner` | Filesystem walk, binary and manifest detection, `CryptoFinding` model |
| `lockfile` | `Cargo.lock`, npm, Poetry and Pipenv lockfile parsing → resolved versions |
| `advisories` | Advisory DB loading (RustSec/OSV), version matching, CVSS v3 scoring |
| `pep440` | PEP 440 version parsing and total ordering, for PyPI comparisons |
| `cbom` | CycloneDX 1.6 CBOM construction |
| `sarif` | SARIF 2.1.0 log construction |
| `library` | Shared scan-result types (`LibraryInfo`, `LibraryCategory`, `RiskLevel`) |

Full API documentation: [docs.rs/lens3329](https://docs.rs/lens3329).

## Scope and limitations

Please read this before relying on the output.

- **Algorithm assets in the CBOM are inferred from library identity, not from
  observed runtime calls.** An algorithm component means "this library can do
  X", not "X is actually invoked". Versions and transitive dependencies, by
  contrast, are evidence-based — they come from lockfiles.
- **Only lockfile-resolved versions are correlated against advisories.**
  Declared-only ranges are skipped rather than guessed, and a version that
  fails its ecosystem's parser matches nothing rather than being assumed
  vulnerable.
- **Advisory coverage is limited to the database you supply**, and to the
  Cargo, npm and PyPI ecosystems. This is not a replacement for `cargo audit`,
  `npm audit` or `pip-audit` — it is a cryptography-focused inventory that also
  correlates, and it is best run alongside them.
- **Quantum-risk flags are a property of the algorithm, not of your usage.**
  A library marked Shor-breakable may be used for something a quantum computer
  does not threaten.

Correlation is validated against the real OSV exports rather than hand-written
fixtures, which is how four silent range-matching defects were found and fixed;
see `tests/osv_corpus.rs`.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Note that
for a scanner, a **silent false negative is a security issue**, not a cosmetic
one: if `--fail-on` passes when it should have failed, we want to hear about it.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

Copyright 2026 Lomyen Ltd.
