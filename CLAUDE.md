# 3329lens — notes for Claude Code

3329lens is a cryptographic inventory scanner. It finds crypto libraries and dependencies, resolves
versions from lockfiles (Cargo, npm, PyPI), correlates them offline against an advisory database,
and exports CycloneDX 1.6 CBOM and SARIF 2.1.0. Apache-2.0. See `README.md` for usage and
`CHANGELOG.md` for release history.

## Naming

The product, GitHub org, domain and binary are `3329lens`; the **crate is `lens3329`**, because
Cargo rejects package names that start with a digit. Use `lens3329::` in Rust code and `3329lens`
everywhere a user sees it.

## Layout

- `src/lib.rs` is the UI-free core library: `scanner`, `lockfile`, `advisories`, `pep440`,
  `library`, `cbom`, `sarif`, `tool`.
- `src/cli.rs` and `src/scanner_dashboard/` (Ratatui TUI) sit behind the default-on **`cli`
  feature**. The binary (`src/main.rs`) requires it.
- `lib.rs` declares `extern crate self as scanner_core;`, so modules may refer to this crate as
  `scanner_core::`. That's a leftover alias from when the code moved here, not a separate crate.
- `tests/osv_corpus.rs` together with `scripts/gen_osv_cases.py` form a differential test against
  real OSV exports. See below.

## Build and test

```bash
cargo build --locked --all-targets
cargo test --locked
cargo test --locked --no-default-features   # library without the CLI/TUI stack
cargo fmt --check
cargo clippy --locked --all-targets
cargo package --locked                      # catches publish metadata problems early
```

CI (`.github/workflows/ci.yml`) runs all of this on Linux, macOS and Windows with
**`RUSTFLAGS: -D warnings`**, so any rustc or clippy warning fails the build. CI uses a floating
`stable` toolchain, so **run `rustup update` before trusting a local green**: a newer stable can add
lints an older local toolchain doesn't report.

- **MSRV is 1.88** (`rust-version` in `Cargo.toml`). Don't use language or std features newer than
  that without raising it deliberately, and record the change in `CHANGELOG.md`.
- **Keep the core building without `cli`.** Library consumers depend on this crate with
  `default-features = false`, and the `lib-only` CI job enforces it. Nothing outside `cli.rs` and
  `scanner_dashboard/` may pull in clap, colored, crossterm or ratatui.
- **The project is portable on purpose**: no assembly and no `build.rs`. Keep it that way.

## The defect class to guard against: silent false negatives

A scanner that quietly matches nothing looks exactly like a clean result. This has happened here
before: the advisory loader once accepted zero real RustSec advisories while every hand-written
fixture test passed, and OSV range handling was wrong in ways that only real data exposed. So:

- **An advisory database that yields zero usable advisories is a hard error (exit 1)**, never "no
  vulnerabilities matched". Don't weaken this.
- **Never guess.** Only lockfile-resolved (`Locked`) versions are correlated, and a version its
  ecosystem's parser rejects matches nothing.
- **Validate parsers against real upstream data, not only fixtures.** For advisory matching, run the
  differential test, whose expected results come from an independent Python implementation (using
  pip's `packaging` for PEP 440):

  ```bash
  curl -O https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip
  unzip -q all.zip -d /tmp/osv-crates
  python3 scripts/gen_osv_cases.py /tmp/osv-crates /tmp/osv-cases.json crates.io
  LENS3329_OSV_CORPUS=/tmp/osv-crates LENS3329_OSV_CASES=/tmp/osv-cases.json \
    cargo test --release --test osv_corpus -- --nocapture
  ```

  It is skipped unless both variables are set, so plain `cargo test` doesn't run it. The doc comment
  in `tests/osv_corpus.rs` mentions a vendored subset in `tests/fixtures/osv/`, but that directory
  has never existed in this repo. The npm corpus hasn't been run through the differential test yet.
- Version matching is ecosystem-aware: semver for Cargo and npm, and the crate's own PEP 440
  comparator (`pep440.rs`) for PyPI. Advisories are keyed by (ecosystem, name), so same-named
  packages in different registries can't cross-match. PyPI names are PEP 503-normalized.

## Compatibility: things that are part of the public contract

Before 1.0, a breaking change bumps the minor version (0.2 → 0.3). Run `cargo semver-checks`
against the last release before publishing.

- **JSON/CBOM enum values**: for example, the SSL/TLS category serializes as `"SslTls"`. Renaming a
  variant changes output that users parse.
- **SARIF fingerprint key** `3329lens/v1` (`FINGERPRINT_KEY` in `sarif.rs`): code-scanning services
  match alerts across runs by it. Changing it makes every existing alert reappear as new.
- **Report tool identity**: `tool::ToolInfo::default()` is 3329lens. Library callers pass their own
  through `findings_to_cbom_with_tool`, `Bom::with_tool` and `sarif::build_with_tool`. Keep the
  non-`_with_tool` functions' signatures stable.
- The public `scanner_dashboard` API exposes ratatui types, so a ratatui upgrade is a breaking change
  (this is why 0.2.0 was not 0.1.1).

## Conventions

- `CHANGELOG.md` follows Keep a Changelog. Add user-visible changes under the next version.
- Exit codes: 0 means OK, 1 means an operational error, and 2 means `--fail-on` threshold reached.
- Algorithm assets in the CBOM are inferred from library identity, not observed at runtime. Keep
  that distinction honest in docs and output.
- Security issues go through GitHub private vulnerability reporting (see `SECURITY.md`), not
  public issues.
