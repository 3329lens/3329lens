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
 *
 * Part of the Slow Lynx Cryptography Discovery project.
 */

use std::collections::HashMap;
use std::path::Path;

use crate::scanner::{normalize_pypi_name, read_file_with_limit, MAX_MANIFEST_SIZE};

/// Parse a `Cargo.lock` into a map of crate name -> resolved version.
///
/// Reuses the scanner's DoS-guarded reader (`MAX_MANIFEST_SIZE`). Returns `None`
/// if the file is unreadable, too large, or not valid lock TOML. A crate can in
/// principle appear multiple times (duplicate versions in the graph); we keep
/// the first occurrence, which is sufficient for identity + advisory lookup.
pub fn parse_cargo_lock(path: &Path) -> Option<HashMap<String, String>> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let packages = parsed.get("package")?.as_array()?;

    let mut map = HashMap::new();
    for pkg in packages {
        if let (Some(name), Some(version)) = (
            pkg.get("name").and_then(|v| v.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) {
            map.entry(name.to_string())
                .or_insert_with(|| version.to_string());
        }
    }
    Some(map)
}

/// Given a `Cargo.toml` path, resolve versions from a sibling `Cargo.lock`.
///
/// Returns `None` when no lockfile sits next to the manifest, in which case the
/// caller falls back to declared manifest requirements.
pub fn resolve_from_sibling_lock(manifest_path: &Path) -> Option<HashMap<String, String>> {
    let lock_path = manifest_path.parent()?.join("Cargo.lock");
    if lock_path.is_file() {
        parse_cargo_lock(&lock_path)
    } else {
        None
    }
}

/// Parse an npm `package-lock.json` / `npm-shrinkwrap.json` into a map of
/// package name -> resolved version.
///
/// Handles both lockfile formats:
///   - v2/v3: the authoritative `packages` map, keyed by install path
///     (`node_modules/foo`, `node_modules/@scope/bar`, nested paths). The
///     package name is the segment after the last `node_modules/`.
///   - v1: the legacy nested `dependencies` map, walked recursively.
/// When both are present (v2 keeps `dependencies` for back-compat), `packages`
/// wins. First occurrence of a name is kept. Returns `None` on unreadable,
/// oversized, or non-JSON input.
pub fn parse_npm_lock(path: &Path) -> Option<HashMap<String, String>> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mut map = HashMap::new();

    // Preferred: v2/v3 `packages` map.
    if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            // The root project is keyed by "" — it is not a dependency.
            let name = match npm_name_from_packages_key(key) {
                Some(n) => n,
                None => continue,
            };
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                map.entry(name).or_insert_with(|| version.to_string());
            }
        }
        if !map.is_empty() {
            return Some(map);
        }
    }

    // Fallback: v1 nested `dependencies` map.
    if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
        collect_npm_v1_deps(deps, &mut map);
    }

    Some(map)
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

/// Recursively collect name -> version from a v1 `dependencies` object,
/// descending into nested `dependencies`. First occurrence wins.
fn collect_npm_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    map: &mut HashMap<String, String>,
) {
    for (name, entry) in deps {
        if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
            map.entry(name.clone())
                .or_insert_with(|| version.to_string());
        }
        if let Some(nested) = entry.get("dependencies").and_then(|v| v.as_object()) {
            collect_npm_v1_deps(nested, map);
        }
    }
}

/// Given a `package.json` path, resolve versions from a sibling npm lockfile.
///
/// Prefers `package-lock.json`, then `npm-shrinkwrap.json`. Returns `None` when
/// neither sits next to the manifest, in which case the caller falls back to
/// declared manifest requirements.
pub fn resolve_npm_from_sibling_lock(manifest_path: &Path) -> Option<HashMap<String, String>> {
    let dir = manifest_path.parent()?;
    for candidate in ["package-lock.json", "npm-shrinkwrap.json"] {
        let lock_path = dir.join(candidate);
        if lock_path.is_file() {
            if let Some(map) = parse_npm_lock(&lock_path) {
                return Some(map);
            }
        }
    }
    None
}

/// Parse a `poetry.lock` into a map of PEP 503-normalized package name ->
/// resolved version. Structurally a TOML `[[package]]` array, like Cargo.
/// Returns `None` on unreadable/oversized/non-TOML input.
pub fn parse_poetry_lock(path: &Path) -> Option<HashMap<String, String>> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let packages = parsed.get("package")?.as_array()?;

    let mut map = HashMap::new();
    for pkg in packages {
        if let (Some(name), Some(version)) = (
            pkg.get("name").and_then(|v| v.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) {
            map.entry(normalize_pypi_name(name))
                .or_insert_with(|| version.to_string());
        }
    }
    Some(map)
}

/// Parse a `Pipfile.lock` into a map of PEP 503-normalized package name ->
/// resolved version. JSON with `default` and `develop` objects, each keyed by
/// package name; the value's `version` is a pinned `"==x.y.z"` string.
/// Returns `None` on unreadable/oversized/non-JSON input.
pub fn parse_pipfile_lock(path: &Path) -> Option<HashMap<String, String>> {
    let content = read_file_with_limit(path, MAX_MANIFEST_SIZE).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mut map = HashMap::new();
    for section in ["default", "develop"] {
        if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
            for (name, entry) in obj {
                if let Some(raw) = entry.get("version").and_then(|v| v.as_str()) {
                    // Strip a leading "==" (the only operator Pipfile.lock uses).
                    let version = raw.trim_start_matches('=').trim();
                    if !version.is_empty() {
                        map.entry(normalize_pypi_name(name))
                            .or_insert_with(|| version.to_string());
                    }
                }
            }
        }
    }
    Some(map)
}

/// Given a PyPI manifest path, resolve versions from its sibling lockfile:
/// `pyproject.toml` -> `poetry.lock`, `Pipfile` -> `Pipfile.lock`. Returns
/// `None` when no matching sibling lock is present.
pub fn resolve_pypi_from_sibling_lock(manifest_path: &Path) -> Option<HashMap<String, String>> {
    let dir = manifest_path.parent()?;
    let manifest = manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let (lock_name, parse): (&str, fn(&Path) -> Option<HashMap<String, String>>) = match manifest {
        "pyproject.toml" => ("poetry.lock", parse_poetry_lock),
        "Pipfile" => ("Pipfile.lock", parse_pipfile_lock),
        _ => return None,
    };
    let lock_path = dir.join(lock_name);
    if lock_path.is_file() {
        parse(&lock_path)
    } else {
        None
    }
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
            "slow_lynx_lockfile_test_{}_{}",
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
        let map = parse_cargo_lock(&lock).expect("lock should parse");
        assert_eq!(map.get("ring").map(String::as_str), Some("0.17.8"));
        assert_eq!(map.get("rustls").map(String::as_str), Some("0.21.10"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_from_sibling_lock() {
        let dir = temp_dir("sibling");
        write_file(&dir, "Cargo.lock", SAMPLE_LOCK);
        let manifest = write_file(&dir, "Cargo.toml", "[package]\nname = \"x\"\n");
        let map = resolve_from_sibling_lock(&manifest).expect("sibling lock resolves");
        assert_eq!(map.get("ring").map(String::as_str), Some("0.17.8"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_lock_returns_none() {
        let dir = temp_dir("nolock");
        let manifest = write_file(&dir, "Cargo.toml", "[package]\nname = \"x\"\n");
        assert!(resolve_from_sibling_lock(&manifest).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_lock_returns_none() {
        let dir = temp_dir("malformed");
        let lock = write_file(&dir, "Cargo.lock", "this is not valid toml ::: {");
        assert!(parse_cargo_lock(&lock).is_none());
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
        let map = parse_npm_lock(&lock).expect("npm v3 lock should parse");
        assert_eq!(map.get("node-forge").map(String::as_str), Some("1.3.1"));
        assert_eq!(
            map.get("@scope/cryptolib").map(String::as_str),
            Some("2.4.0")
        );
        // Transitive dep nested under another package is surfaced.
        assert_eq!(map.get("bcrypt").map(String::as_str), Some("5.1.0"));
        // Root ("") and link-only entries contribute no version.
        assert!(!map.contains_key(""));
        assert!(!map.contains_key("linked"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_npm_v1_nested_dependencies() {
        let dir = temp_dir("npm_v1");
        let lock = write_file(&dir, "package-lock.json", SAMPLE_NPM_LOCK_V1);
        let map = parse_npm_lock(&lock).expect("npm v1 lock should parse");
        assert_eq!(map.get("node-forge").map(String::as_str), Some("1.3.1"));
        assert_eq!(map.get("bcrypt").map(String::as_str), Some("5.1.0"));
        assert_eq!(map.get("crypto-js").map(String::as_str), Some("4.2.0"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_npm_from_sibling_lock_and_shrinkwrap() {
        let dir = temp_dir("npm_sibling");
        write_file(&dir, "package-lock.json", SAMPLE_NPM_LOCK_V3);
        let manifest = write_file(&dir, "package.json", "{\"name\":\"demo\"}");
        let map = resolve_npm_from_sibling_lock(&manifest).expect("sibling npm lock resolves");
        assert_eq!(map.get("node-forge").map(String::as_str), Some("1.3.1"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn npm_no_lock_returns_none() {
        let dir = temp_dir("npm_nolock");
        let manifest = write_file(&dir, "package.json", "{\"name\":\"demo\"}");
        assert!(resolve_npm_from_sibling_lock(&manifest).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_npm_lock_returns_none() {
        let dir = temp_dir("npm_malformed");
        let lock = write_file(&dir, "package-lock.json", "{ not valid json ");
        assert!(parse_npm_lock(&lock).is_none());
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
        let map = parse_poetry_lock(&lock).expect("poetry lock should parse");
        assert_eq!(map.get("cryptography").map(String::as_str), Some("41.0.7"));
        // PyOpenSSL normalizes to pyopenssl.
        assert_eq!(map.get("pyopenssl").map(String::as_str), Some("23.3.0"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_pipfile_lock_default_and_develop() {
        let dir = temp_dir("pipfile");
        let lock = write_file(&dir, "Pipfile.lock", SAMPLE_PIPFILE_LOCK);
        let map = parse_pipfile_lock(&lock).expect("Pipfile.lock should parse");
        assert_eq!(map.get("cryptography").map(String::as_str), Some("41.0.7"));
        assert_eq!(map.get("pynacl").map(String::as_str), Some("1.5.0")); // == stripped
        assert_eq!(map.get("bcrypt").map(String::as_str), Some("4.1.2")); // develop section
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_pypi_lock_by_manifest_kind() {
        let dir = temp_dir("pypi_sibling");
        write_file(&dir, "poetry.lock", SAMPLE_POETRY_LOCK);
        let pyproject = write_file(&dir, "pyproject.toml", "[tool.poetry]\nname = \"x\"\n");
        let map = resolve_pypi_from_sibling_lock(&pyproject).expect("poetry sibling resolves");
        assert_eq!(map.get("cryptography").map(String::as_str), Some("41.0.7"));

        write_file(&dir, "Pipfile.lock", SAMPLE_PIPFILE_LOCK);
        let pipfile = write_file(&dir, "Pipfile", "[packages]\n");
        let map2 = resolve_pypi_from_sibling_lock(&pipfile).expect("pipenv sibling resolves");
        assert_eq!(map2.get("pynacl").map(String::as_str), Some("1.5.0"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pypi_no_sibling_lock_returns_none() {
        let dir = temp_dir("pypi_nolock");
        let pyproject = write_file(&dir, "pyproject.toml", "[tool.poetry]\nname = \"x\"\n");
        assert!(resolve_pypi_from_sibling_lock(&pyproject).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
