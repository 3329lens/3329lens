/*
 * Lockfile Resolution Module - Defensive Security
 *
 * Resolves *actual deployed* dependency versions from lockfiles, as opposed to
 * the declared requirements parsed from manifests. Resolved versions are the
 * prerequisite for evidence-based work downstream:
 *   - accurate CycloneDX purls (pkg:cargo/<name>@<resolved>)
 *   - advisory / CVE correlation (which needs a concrete version, not a range)
 *   - transitive crypto discovery (crates pulled in indirectly)
 *
 * Scope: Cargo (Cargo.lock), npm (package-lock.json / npm-shrinkwrap.json), and
 * PyPI (poetry.lock / Pipfile.lock). PyPI package names are stored PEP 503-
 * normalized so they compare equal to findings and OSV advisory names.
 */

use std::collections::HashMap;
use std::path::Path;

use crate::scanner::{normalize_pypi_name, read_file_with_limit, MAX_MANIFEST_SIZE};

/// Every resolved version of every package in one lockfile.
///
/// A lockfile can hold several versions of the same package: two majors of
/// `rustls` in one `Cargo.lock`, or a nested copy of an npm package under
/// another one. Each of those is installed, so each must be checked against
/// advisories. Recording only one version per name hides the others, which
/// is a silent false negative.
///
/// Versions are kept in the order the lockfile lists them, without duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockedPackages {
    versions: HashMap<String, Vec<String>>,
    top_level: HashMap<String, String>,
}

impl LockedPackages {
    /// Every resolved version of `name`, in lockfile order. Empty if the
    /// lockfile does not contain the package.
    pub fn versions(&self, name: &str) -> &[String] {
        self.versions.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The version installed at the top level of the project, when the
    /// lockfile records one: `node_modules/<name>` in npm v2/v3, or a top-level
    /// `dependencies` entry in npm v1. This is the copy the project's own
    /// `require`/`import` resolves to. Always `None` for Cargo and PyPI
    /// lockfiles, which have no such notion.
    pub fn top_level(&self, name: &str) -> Option<&str> {
        self.top_level.get(name).map(String::as_str)
    }

    /// True if the lockfile resolved no packages at all.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Record a resolved version, ignoring exact duplicates.
    pub(crate) fn insert(&mut self, name: String, version: &str) {
        let versions = self.versions.entry(name).or_default();
        if !versions.iter().any(|v| v == version) {
            versions.push(version.to_string());
        }
    }

    /// The first version recorded for each package. This is the lossy shape
    /// the deprecated single-version parsers return.
    fn first_versions(self) -> HashMap<String, String> {
        self.versions
            .into_iter()
            .filter_map(|(name, versions)| versions.into_iter().next().map(|v| (name, v)))
            .collect()
    }
}

/// A lockfile parser, selected by the manifest sitting beside it.
type LockParser = fn(&Path) -> Option<LockedPackages>;

/// Parse a `Cargo.lock` into every resolved version of every crate.
///
/// Reuses the scanner's DoS-guarded reader (`MAX_MANIFEST_SIZE`). Returns `None`
/// if the file is unreadable, too large, or not valid lock TOML.
pub fn parse_cargo_lock_all(path: &Path) -> Option<LockedPackages> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let packages = parsed.get("package")?.as_array()?;

    let mut lock = LockedPackages::default();
    for pkg in packages {
        if let (Some(name), Some(version)) = (
            pkg.get("name").and_then(|v| v.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) {
            lock.insert(name.to_string(), version);
        }
    }
    Some(lock)
}

/// Parse a `Cargo.lock` into a map of crate name -> one resolved version.
///
/// Returns `None` if the file is unreadable, too large, or not valid lock TOML.
#[deprecated(
    since = "0.2.2",
    note = "keeps only the first version of each crate, so other versions are never \
            checked against advisories; use `parse_cargo_lock_all`"
)]
pub fn parse_cargo_lock(path: &Path) -> Option<HashMap<String, String>> {
    parse_cargo_lock_all(path).map(LockedPackages::first_versions)
}

/// Given a `Cargo.toml` path, resolve every version from a sibling `Cargo.lock`.
///
/// Returns `None` when no lockfile sits next to the manifest, in which case the
/// caller falls back to declared manifest requirements.
pub fn resolve_from_sibling_lock_all(manifest_path: &Path) -> Option<LockedPackages> {
    let lock_path = manifest_path.parent()?.join("Cargo.lock");
    if lock_path.is_file() {
        parse_cargo_lock_all(&lock_path)
    } else {
        None
    }
}

/// Given a `Cargo.toml` path, resolve one version per crate from a sibling
/// `Cargo.lock`.
#[deprecated(
    since = "0.2.2",
    note = "keeps only the first version of each crate, so other versions are never \
            checked against advisories; use `resolve_from_sibling_lock_all`"
)]
pub fn resolve_from_sibling_lock(manifest_path: &Path) -> Option<HashMap<String, String>> {
    resolve_from_sibling_lock_all(manifest_path).map(LockedPackages::first_versions)
}

/// Parse an npm `package-lock.json` / `npm-shrinkwrap.json` into every
/// resolved version of every package.
///
/// Handles both lockfile formats:
///   - v2/v3: the authoritative `packages` map, keyed by install path
///     (`node_modules/foo`, `node_modules/@scope/bar`, nested paths). The
///     package name is the segment after the last `node_modules/`.
///   - v1: the legacy nested `dependencies` map, walked recursively.
///
/// When both are present (v2 keeps `dependencies` for back-compat), `packages`
/// wins. Returns `None` on unreadable, oversized, or non-JSON input.
pub fn parse_npm_lock_all(path: &Path) -> Option<LockedPackages> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mut lock = LockedPackages::default();

    // Preferred: v2/v3 `packages` map.
    if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            // The root project is keyed by "" — it is not a dependency.
            let name = match npm_name_from_packages_key(key) {
                Some(n) => n,
                None => continue,
            };
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                if key.strip_prefix("node_modules/") == Some(name.as_str()) {
                    lock.top_level.insert(name.clone(), version.to_string());
                }
                lock.insert(name, version);
            }
        }
        if !lock.is_empty() {
            return Some(lock);
        }
    }

    // Fallback: v1 nested `dependencies` map.
    if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
        for (name, entry) in deps {
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                lock.top_level.insert(name.clone(), version.to_string());
            }
        }
        collect_npm_v1_deps(deps, &mut lock);
    }

    Some(lock)
}

/// Parse an npm `package-lock.json` / `npm-shrinkwrap.json` into a map of
/// package name -> one resolved version.
#[deprecated(
    since = "0.2.2",
    note = "keeps only the first version of each package, so other versions are never \
            checked against advisories; use `parse_npm_lock_all`"
)]
pub fn parse_npm_lock(path: &Path) -> Option<HashMap<String, String>> {
    parse_npm_lock_all(path).map(LockedPackages::first_versions)
}

/// Derive a package name from a v2/v3 `packages` key such as
/// `node_modules/@scope/pkg/node_modules/dep`. Returns `None` for the root
/// (`""`) and for workspace/local paths that contain no `node_modules/`.
fn npm_name_from_packages_key(key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let idx = key.rfind("node_modules/")?;
    let name = &key[idx + "node_modules/".len()..];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Recursively collect every name -> version from a v1 `dependencies` object,
/// descending into nested `dependencies`.
fn collect_npm_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    lock: &mut LockedPackages,
) {
    for (name, entry) in deps {
        if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
            lock.insert(name.clone(), version);
        }
        if let Some(nested) = entry.get("dependencies").and_then(|v| v.as_object()) {
            collect_npm_v1_deps(nested, lock);
        }
    }
}

/// Given a `package.json` path, resolve every version from a sibling npm
/// lockfile.
///
/// Prefers `package-lock.json`, then `npm-shrinkwrap.json`. Returns `None` when
/// neither sits next to the manifest, in which case the caller falls back to
/// declared manifest requirements.
pub fn resolve_npm_from_sibling_lock_all(manifest_path: &Path) -> Option<LockedPackages> {
    let dir = manifest_path.parent()?;
    for candidate in ["package-lock.json", "npm-shrinkwrap.json"] {
        let lock_path = dir.join(candidate);
        if lock_path.is_file() {
            if let Some(lock) = parse_npm_lock_all(&lock_path) {
                return Some(lock);
            }
        }
    }
    None
}

/// Given a `package.json` path, resolve one version per package from a sibling
/// npm lockfile.
#[deprecated(
    since = "0.2.2",
    note = "keeps only the first version of each package, so other versions are never \
            checked against advisories; use `resolve_npm_from_sibling_lock_all`"
)]
pub fn resolve_npm_from_sibling_lock(manifest_path: &Path) -> Option<HashMap<String, String>> {
    resolve_npm_from_sibling_lock_all(manifest_path).map(LockedPackages::first_versions)
}

/// Parse a `poetry.lock` into every resolved version of every package, keyed
/// by PEP 503-normalized name. Structurally a TOML `[[package]]` array, like
/// Cargo. Returns `None` on unreadable/oversized/non-TOML input.
pub fn parse_poetry_lock_all(path: &Path) -> Option<LockedPackages> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let packages = parsed.get("package")?.as_array()?;

    let mut lock = LockedPackages::default();
    for pkg in packages {
        if let (Some(name), Some(version)) = (
            pkg.get("name").and_then(|v| v.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) {
            lock.insert(normalize_pypi_name(name), version);
        }
    }
    Some(lock)
}

/// Parse a `poetry.lock` into a map of PEP 503-normalized package name -> one
/// resolved version.
#[deprecated(
    since = "0.2.2",
    note = "keeps only the first version of each package, so other versions are never \
            checked against advisories; use `parse_poetry_lock_all`"
)]
pub fn parse_poetry_lock(path: &Path) -> Option<HashMap<String, String>> {
    parse_poetry_lock_all(path).map(LockedPackages::first_versions)
}

/// Parse a `Pipfile.lock` into every resolved version of every package, keyed
/// by PEP 503-normalized name. JSON with `default` and `develop` objects, each
/// keyed by package name; the value's `version` is a pinned `"==x.y.z"` string.
/// The two sections can pin different versions of one package, and both are
/// kept. Returns `None` on unreadable/oversized/non-JSON input.
pub fn parse_pipfile_lock_all(path: &Path) -> Option<LockedPackages> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mut lock = LockedPackages::default();
    for section in ["default", "develop"] {
        if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
            for (name, entry) in obj {
                if let Some(raw) = entry.get("version").and_then(|v| v.as_str()) {
                    // Strip a leading "==" (the only operator Pipfile.lock uses).
                    let version = raw.trim_start_matches('=').trim();
                    if !version.is_empty() {
                        lock.insert(normalize_pypi_name(name), version);
                    }
                }
            }
        }
    }
    Some(lock)
}

/// Parse a `Pipfile.lock` into a map of PEP 503-normalized package name -> one
/// resolved version.
#[deprecated(
    since = "0.2.2",
    note = "keeps only the first version of each package, so other versions are never \
            checked against advisories; use `parse_pipfile_lock_all`"
)]
pub fn parse_pipfile_lock(path: &Path) -> Option<HashMap<String, String>> {
    parse_pipfile_lock_all(path).map(LockedPackages::first_versions)
}

/// Given a PyPI manifest path, resolve every version from its sibling lockfile:
/// `pyproject.toml` -> `poetry.lock`, `Pipfile` -> `Pipfile.lock`. Returns
/// `None` when no matching sibling lock is present.
pub fn resolve_pypi_from_sibling_lock_all(manifest_path: &Path) -> Option<LockedPackages> {
    let dir = manifest_path.parent()?;
    let manifest = manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let (lock_name, parse): (&str, LockParser) = match manifest {
        "pyproject.toml" => ("poetry.lock", parse_poetry_lock_all),
        "Pipfile" => ("Pipfile.lock", parse_pipfile_lock_all),
        _ => return None,
    };
    let lock_path = dir.join(lock_name);
    if lock_path.is_file() {
        parse(&lock_path)
    } else {
        None
    }
}

/// Given a PyPI manifest path, resolve one version per package from its
/// sibling lockfile.
#[deprecated(
    since = "0.2.2",
    note = "keeps only the first version of each package, so other versions are never \
            checked against advisories; use `resolve_pypi_from_sibling_lock_all`"
)]
pub fn resolve_pypi_from_sibling_lock(manifest_path: &Path) -> Option<HashMap<String, String>> {
    resolve_pypi_from_sibling_lock_all(manifest_path).map(LockedPackages::first_versions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write a string to `dir/name` and return the full path.
    fn write_file(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    /// A unique temp dir under the system temp root for an isolated fixture.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "lens3329_lockfile_test_{}_{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SAMPLE_LOCK: &str = r#"
version = 3

[[package]]
name = "ring"
version = "0.17.8"

[[package]]
name = "rustls"
version = "0.21.10"

[[package]]
name = "some-unrelated-crate"
version = "1.2.3"
"#;

    #[test]
    fn parses_name_and_version_pairs() {
        let dir = temp_dir("parse");
        let lock = write_file(&dir, "Cargo.lock", SAMPLE_LOCK);
        let map = parse_cargo_lock_all(&lock).expect("lock should parse");
        assert_eq!(map.versions("ring"), ["0.17.8"]);
        assert_eq!(map.versions("rustls"), ["0.21.10"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_from_sibling_lock() {
        let dir = temp_dir("sibling");
        write_file(&dir, "Cargo.lock", SAMPLE_LOCK);
        let manifest = write_file(&dir, "Cargo.toml", "[package]\nname = \"x\"\n");
        let map = resolve_from_sibling_lock_all(&manifest).expect("sibling lock resolves");
        assert_eq!(map.versions("ring"), ["0.17.8"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_lock_returns_none() {
        let dir = temp_dir("nolock");
        let manifest = write_file(&dir, "Cargo.toml", "[package]\nname = \"x\"\n");
        assert!(resolve_from_sibling_lock_all(&manifest).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_lock_returns_none() {
        let dir = temp_dir("malformed");
        let lock = write_file(&dir, "Cargo.lock", "this is not valid toml ::: {");
        assert!(parse_cargo_lock_all(&lock).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    // npm lockfile v2/v3: authoritative `packages` map, including a scoped name
    // and a nested (transitive) install path.
    const SAMPLE_NPM_LOCK_V3: &str = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/node-forge": { "version": "1.3.1" },
    "node_modules/@scope/cryptolib": { "version": "2.4.0" },
    "node_modules/node-forge/node_modules/bcrypt": { "version": "5.1.0" },
    "node_modules/linked": { "link": true }
  }
}"#;

    // npm lockfile v1: legacy nested `dependencies` map.
    const SAMPLE_NPM_LOCK_V1: &str = r#"{
  "name": "demo",
  "lockfileVersion": 1,
  "dependencies": {
    "node-forge": {
      "version": "1.3.1",
      "dependencies": {
        "bcrypt": { "version": "5.1.0" }
      }
    },
    "crypto-js": { "version": "4.2.0" }
  }
}"#;

    #[test]
    fn parses_npm_v3_packages_with_scope_and_nesting() {
        let dir = temp_dir("npm_v3");
        let lock = write_file(&dir, "package-lock.json", SAMPLE_NPM_LOCK_V3);
        let map = parse_npm_lock_all(&lock).expect("npm v3 lock should parse");
        assert_eq!(map.versions("node-forge"), ["1.3.1"]);
        assert_eq!(map.versions("@scope/cryptolib"), ["2.4.0"]);
        // Transitive dep nested under another package is surfaced.
        assert_eq!(map.versions("bcrypt"), ["5.1.0"]);
        // Root ("") and link-only entries contribute no version.
        assert!(map.versions("").is_empty());
        assert!(map.versions("linked").is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_npm_v1_nested_dependencies() {
        let dir = temp_dir("npm_v1");
        let lock = write_file(&dir, "package-lock.json", SAMPLE_NPM_LOCK_V1);
        let map = parse_npm_lock_all(&lock).expect("npm v1 lock should parse");
        assert_eq!(map.versions("node-forge"), ["1.3.1"]);
        assert_eq!(map.versions("bcrypt"), ["5.1.0"]);
        assert_eq!(map.versions("crypto-js"), ["4.2.0"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_npm_from_sibling_lock_and_shrinkwrap() {
        let dir = temp_dir("npm_sibling");
        write_file(&dir, "package-lock.json", SAMPLE_NPM_LOCK_V3);
        let manifest = write_file(&dir, "package.json", "{\"name\":\"demo\"}");
        let map = resolve_npm_from_sibling_lock_all(&manifest).expect("sibling npm lock resolves");
        assert_eq!(map.versions("node-forge"), ["1.3.1"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn npm_no_lock_returns_none() {
        let dir = temp_dir("npm_nolock");
        let manifest = write_file(&dir, "package.json", "{\"name\":\"demo\"}");
        assert!(resolve_npm_from_sibling_lock_all(&manifest).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_npm_lock_returns_none() {
        let dir = temp_dir("npm_malformed");
        let lock = write_file(&dir, "package-lock.json", "{ not valid json ");
        assert!(parse_npm_lock_all(&lock).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    // poetry.lock: TOML [[package]] array; names normalized (PyOpenSSL/PyNaCl).
    const SAMPLE_POETRY_LOCK: &str = r#"
[[package]]
name = "cryptography"
version = "41.0.7"

[[package]]
name = "PyOpenSSL"
version = "23.3.0"

[[package]]
name = "requests"
version = "2.31.0"
"#;

    // Pipfile.lock: JSON with default + develop sections and "==" versions.
    const SAMPLE_PIPFILE_LOCK: &str = r#"{
  "default": {
    "cryptography": { "version": "==41.0.7" },
    "PyNaCl": { "version": "==1.5.0" }
  },
  "develop": {
    "bcrypt": { "version": "==4.1.2" }
  }
}"#;

    #[test]
    fn parses_poetry_lock_with_normalized_names() {
        let dir = temp_dir("poetry");
        let lock = write_file(&dir, "poetry.lock", SAMPLE_POETRY_LOCK);
        let map = parse_poetry_lock_all(&lock).expect("poetry lock should parse");
        assert_eq!(map.versions("cryptography"), ["41.0.7"]);
        // PyOpenSSL normalizes to pyopenssl.
        assert_eq!(map.versions("pyopenssl"), ["23.3.0"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_pipfile_lock_default_and_develop() {
        let dir = temp_dir("pipfile");
        let lock = write_file(&dir, "Pipfile.lock", SAMPLE_PIPFILE_LOCK);
        let map = parse_pipfile_lock_all(&lock).expect("Pipfile.lock should parse");
        assert_eq!(map.versions("cryptography"), ["41.0.7"]);
        assert_eq!(map.versions("pynacl"), ["1.5.0"]); // == stripped
        assert_eq!(map.versions("bcrypt"), ["4.1.2"]); // develop section
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_pypi_lock_by_manifest_kind() {
        let dir = temp_dir("pypi_sibling");
        write_file(&dir, "poetry.lock", SAMPLE_POETRY_LOCK);
        let pyproject = write_file(&dir, "pyproject.toml", "[tool.poetry]\nname = \"x\"\n");
        let map = resolve_pypi_from_sibling_lock_all(&pyproject).expect("poetry sibling resolves");
        assert_eq!(map.versions("cryptography"), ["41.0.7"]);

        write_file(&dir, "Pipfile.lock", SAMPLE_PIPFILE_LOCK);
        let pipfile = write_file(&dir, "Pipfile", "[packages]\n");
        let map2 = resolve_pypi_from_sibling_lock_all(&pipfile).expect("pipenv sibling resolves");
        assert_eq!(map2.versions("pynacl"), ["1.5.0"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pypi_no_sibling_lock_returns_none() {
        let dir = temp_dir("pypi_nolock");
        let pyproject = write_file(&dir, "pyproject.toml", "[tool.poetry]\nname = \"x\"\n");
        assert!(resolve_pypi_from_sibling_lock_all(&pyproject).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    // Two majors of one crate side by side, as Cargo writes them (sorted by
    // name, then version). Both are compiled into the build.
    const MULTI_VERSION_CARGO_LOCK: &str = r#"
version = 3

[[package]]
name = "rustls"
version = "0.21.12"

[[package]]
name = "rustls"
version = "0.23.35"

[[package]]
name = "ring"
version = "0.17.14"
"#;

    #[test]
    fn cargo_lock_keeps_every_version_of_a_crate() {
        let dir = temp_dir("cargo_multi");
        let lock = write_file(&dir, "Cargo.lock", MULTI_VERSION_CARGO_LOCK);
        let lock = parse_cargo_lock_all(&lock).expect("lock should parse");
        assert_eq!(lock.versions("rustls"), ["0.21.12", "0.23.35"]);
        assert_eq!(lock.versions("ring"), ["0.17.14"]);
        assert!(lock.versions("absent").is_empty());
        // Cargo has no notion of a top-level copy.
        assert_eq!(lock.top_level("rustls"), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn npm_v3_keeps_nested_copies_and_marks_the_top_level_one() {
        // The nested copy sorts *before* the top-level one, so "first
        // occurrence" would pick the copy the project does not import.
        let dir = temp_dir("npm_multi");
        let lock = write_file(
            &dir,
            "package-lock.json",
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo" },
    "node_modules/a-dep/node_modules/node-forge": { "version": "0.10.0" },
    "node_modules/node-forge": { "version": "1.3.1" },
    "node_modules/z-dep/node_modules/node-forge": { "version": "1.3.1" }
  }
}"#,
        );
        let lock = parse_npm_lock_all(&lock).expect("npm lock should parse");
        assert_eq!(lock.versions("node-forge"), ["0.10.0", "1.3.1"]);
        assert_eq!(lock.top_level("node-forge"), Some("1.3.1"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn npm_v1_keeps_nested_copies_and_marks_the_top_level_one() {
        let dir = temp_dir("npm_v1_multi");
        let lock = write_file(
            &dir,
            "package-lock.json",
            r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "a-dep": {
      "version": "1.0.0",
      "dependencies": { "node-forge": { "version": "0.10.0" } }
    },
    "node-forge": { "version": "1.3.1" }
  }
}"#,
        );
        let lock = parse_npm_lock_all(&lock).expect("npm v1 lock should parse");
        assert_eq!(lock.versions("node-forge"), ["0.10.0", "1.3.1"]);
        assert_eq!(lock.top_level("node-forge"), Some("1.3.1"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn poetry_and_pipfile_keep_every_version() {
        let dir = temp_dir("pypi_multi");
        let poetry = write_file(
            &dir,
            "poetry.lock",
            "[[package]]\nname = \"cryptography\"\nversion = \"41.0.7\"\n\n\
             [[package]]\nname = \"Cryptography\"\nversion = \"42.0.5\"\n",
        );
        let poetry = parse_poetry_lock_all(&poetry).expect("poetry lock should parse");
        assert_eq!(poetry.versions("cryptography"), ["41.0.7", "42.0.5"]);

        let pipfile = write_file(
            &dir,
            "Pipfile.lock",
            r#"{
  "default": { "cryptography": { "version": "==41.0.7" } },
  "develop": { "cryptography": { "version": "==42.0.5" } }
}"#,
        );
        let pipfile = parse_pipfile_lock_all(&pipfile).expect("Pipfile.lock should parse");
        assert_eq!(pipfile.versions("cryptography"), ["41.0.7", "42.0.5"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[allow(deprecated)]
    fn deprecated_parsers_still_return_the_first_version() {
        // Library callers on the old API keep their 0.2.1 behaviour exactly.
        let dir = temp_dir("deprecated");
        let lock = write_file(&dir, "Cargo.lock", MULTI_VERSION_CARGO_LOCK);
        let map = parse_cargo_lock(&lock).expect("lock should parse");
        assert_eq!(map.get("rustls").map(String::as_str), Some("0.21.12"));
        let manifest = write_file(&dir, "Cargo.toml", "[package]\nname = \"x\"\n");
        let map = resolve_from_sibling_lock(&manifest).expect("sibling lock resolves");
        assert_eq!(map.get("ring").map(String::as_str), Some("0.17.14"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
