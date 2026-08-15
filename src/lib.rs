//! Crypto dependency scanner: filesystem/manifest/lockfile scanning,
//! advisory correlation, and CBOM/SARIF report generation.
//!
//! The core library is UI-free. The CLI and the interactive TUI live behind the
//! default-on `cli` feature; depend on this crate with `default-features = false`
//! for the lean correlation core alone.

// Modules moved here from the monorepo refer to this crate as `scanner_core`.
// Aliasing the crate onto that name keeps those paths working unchanged, which
// is what makes the extraction a near-zero-diff move. Collapsing the alias to
// plain `crate::` paths is optional cleanup, not a correctness concern.
extern crate self as scanner_core;

pub mod advisories;
pub mod cbom;
pub mod library;
pub mod lockfile;
pub mod pep440;
pub mod sarif;
pub mod scanner;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub mod scanner_dashboard;
