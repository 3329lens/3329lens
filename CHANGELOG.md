# Changelog

All notable changes to 3329lens (the `lens3329` crate) are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, a
breaking change bumps the minor version (0.1 → 0.2).

## [0.2.0] - 2026-10-07

### Changed

- **Breaking (`cli` feature only):** upgraded `ratatui` 0.26 → 0.30 and
  `crossterm` 0.27 → 0.29. The public `scanner_dashboard` module exposes
  types from these crates in its signatures, for example
  `scanner_dashboard::ui::render(&mut ratatui::Frame, ..)`, so code that calls
  it must use the same `ratatui` version. The scanning and correlation modules
  (`scanner`, `lockfile`, `advisories`, `pep440`, `library`, `cbom`, `sarif`)
  are unchanged.
- **Minimum supported Rust version is now 1.88**, declared as `rust-version`
  in `Cargo.toml`. `ratatui` 0.30 requires it. Older toolchains now get a clear
  "requires rustc 1.88" error from Cargo. This applies to the whole crate,
  including `default-features = false` builds.
- The README install section now has per-platform steps for Linux, macOS,
  Windows and WSL, and recommends `cargo install --locked`.

### Security

- Removes `lru` 0.12, which `ratatui` 0.26 pulled in and which is affected by
  RUSTSEC-2026-0002 (`IterMut` violates Stacked Borrows) and RUSTSEC-2026-0253
  (`pop()` is not panic-safe). Neither was reachable from 3329lens: its only
  `lru` use was `ratatui`'s private layout cache, which calls only `new()`
  and `get_or_insert()`. `ratatui` 0.30 uses `lru` 0.18. `cargo audit` now
  reports no vulnerabilities and no warnings.

## [0.1.0] - 2026-09-25

First release. Scans a codebase for the cryptography it depends on,
resolves versions from Cargo, npm and PyPI lockfiles, correlates them against
an offline RustSec/OSV advisory database, and exports text, JSON, CycloneDX 1.6
CBOM or SARIF 2.1.0. Includes an interactive terminal dashboard.

[0.2.0]: https://github.com/3329lens/3329lens/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/3329lens/3329lens/releases/tag/v0.1.0
