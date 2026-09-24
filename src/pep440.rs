/*
 * PEP 440 Version Parsing & Comparison - Defensive Security
 *
 * Implements the Python version scheme defined by PEP 440 (now the "Version
 * specifiers" spec at packaging.python.org) so PyPI advisory correlation can
 * compare versions that are not valid semver: short release segments (`3.1`),
 * pre-releases (`1.0a1`, `2.0rc1`), post-releases (`1.0.post1`), dev releases
 * (`1.0.dev3`), epochs (`1!2.0`), and local versions (`1.0+local.5`).
 *
 * Ordering follows the spec's total order — the same key construction as
 * pip's `packaging.version.Version`: epoch, then release (trailing zeros
 * insignificant), then dev < pre-release < final < post-release, with local
 * segments as the final tiebreaker (numeric segments outrank alphanumeric).
 *
 * Scope note: [`Requirement`] is a single `op version` comparator as
 * synthesized from OSV range events (`>= fixed`, `< introduced`) and uses
 * plain ordered comparison. This is intentionally NOT pip *specifier*
 * semantics — no prerelease exclusion, no `~=`, no `.*` wildcards — because
 * OSV event semantics are plain ordering over the version total order.
 *
 * Part of the Slow Lynx Cryptography Discovery project.
 */

use std::cmp::Ordering;
use std::sync::OnceLock;

use regex::Regex;

/// Pre-release phase, ordered as the spec requires: alpha < beta < rc.
/// (`c`, `pre`, and `preview` normalize to rc; `alpha`/`beta` to a/b.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PreLabel {
    Alpha,
    Beta,
    Rc,
}

/// One dot-separated segment of a local version (`+ubuntu.1` → [`ubuntu`, 1]).
/// Variant order is significant: numeric segments compare greater than
/// alphanumeric segments, per the spec.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSegment {
    Alpha(String),
    Num(u64),
}

/// A parsed PEP 440 version. Equality and ordering follow the spec's total
/// order, so `1.0 == 1.0.0` and `1.0.dev1 < 1.0a1 < 1.0 < 1.0.post1`.
#[derive(Debug, Clone)]
pub struct Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PreLabel, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Vec<LocalSegment>,
}

/// Position of the pre-release/dev marker in the ordering key. Mirrors
/// `packaging`'s `_cmpkey`: a bare dev release sorts before any pre-release
/// of the same release number, and a final/post release sorts after all of
/// them. Variant order is significant.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreKey {
    BareDev,
    Pre(PreLabel, u64),
    Final,
}

/// The total-order key for a [`Version`], mirroring `packaging`'s `_cmpkey`:
/// epoch, significant release segments, pre/dev marker, post number, dev
/// marker, then local segments. Tuple ordering does the comparison, so the
/// field order here *is* the precedence rule.
type VersionKey<'a> = (
    u64,
    &'a [u64],
    PreKey,
    Option<u64>,
    (bool, u64),
    &'a [LocalSegment],
);

/// Anchored spec regex (lowercased input), per the PEP 440 appendix.
fn version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)^v?
              (?:(?P<epoch>[0-9]+)!)?
              (?P<release>[0-9]+(?:\.[0-9]+)*)
              (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
              (?:
                  (?:-(?P<post_n1>[0-9]+))
                | (?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)
              )?
              (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
              (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
              $",
        )
        .expect("PEP 440 version regex is valid")
    })
}

impl Version {
    /// Parse a PEP 440 version string, applying the spec's normalization
    /// (case-insensitive, `v` prefix, `-`/`_`/`.` separators, spelled-out
    /// phase names). Returns `None` for anything outside the scheme — callers
    /// skip such versions rather than guess.
    pub fn parse(s: &str) -> Option<Version> {
        let normalized = s.trim().to_lowercase();
        let caps = version_re().captures(&normalized)?;

        let num =
            |name: &str| -> Option<u64> { caps.name(name).and_then(|m| m.as_str().parse().ok()) };

        // A present-but-overflowing number is malformed, not "0": bail if a
        // group matched text that doesn't fit u64.
        let num_or_zero = |name: &str| -> Option<u64> {
            match caps.name(name) {
                Some(m) => m.as_str().parse().ok(),
                None => Some(0),
            }
        };

        let epoch = num_or_zero("epoch")?;
        let release = caps["release"]
            .split('.')
            .map(|p| p.parse::<u64>().ok())
            .collect::<Option<Vec<u64>>>()?;

        let pre = match caps.name("pre_l") {
            Some(l) => {
                let label = match l.as_str() {
                    "a" | "alpha" => PreLabel::Alpha,
                    "b" | "beta" => PreLabel::Beta,
                    _ => PreLabel::Rc, // c | rc | pre | preview
                };
                Some((label, num_or_zero("pre_n")?))
            }
            None => None,
        };

        let post = if caps.name("post_n1").is_some() {
            Some(num("post_n1")?)
        } else if caps.name("post_l").is_some() {
            Some(num_or_zero("post_n2")?)
        } else {
            None
        };

        let dev = if caps.name("dev_l").is_some() {
            Some(num_or_zero("dev_n")?)
        } else {
            None
        };

        let local = match caps.name("local") {
            Some(m) => m
                .as_str()
                .split(['-', '_', '.'])
                .map(|seg| match seg.parse::<u64>() {
                    Ok(n) => LocalSegment::Num(n),
                    Err(_) => LocalSegment::Alpha(seg.to_string()),
                })
                .collect(),
            None => Vec::new(),
        };

        Some(Version {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    /// Ordering key per the spec: trailing zeros in the release are
    /// insignificant (`1.0 == 1.0.0`); dev/pre/post markers order around the
    /// final release; local segments break remaining ties.
    fn key(&self) -> VersionKey<'_> {
        let mut end = self.release.len();
        while end > 1 && self.release[end - 1] == 0 {
            end -= 1;
        }

        let pre_key = match (self.pre, self.post, self.dev) {
            (Some((label, n)), _, _) => PreKey::Pre(label, n),
            (None, None, Some(_)) => PreKey::BareDev,
            _ => PreKey::Final,
        };

        // `Option<u64>` orders None < Some(_): no post-release sorts first.
        let post_key = self.post;

        // A dev release sorts before its final counterpart: (false, n) < (true, 0).
        let dev_key = match self.dev {
            Some(n) => (false, n),
            None => (true, 0),
        };

        (
            self.epoch,
            &self.release[..end],
            pre_key,
            post_key,
            dev_key,
            &self.local,
        )
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// Comparison operator of a single-version requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

/// A single `op version` comparator (e.g. `>= 1.4.1`, `< 39.0b1`), matched by
/// plain ordered comparison over the PEP 440 total order. See the module
/// header for why this deliberately isn't pip specifier semantics.
#[derive(Debug, Clone)]
pub struct Requirement {
    op: Op,
    version: Version,
}

impl Requirement {
    /// Parse `op version` with optional whitespace. Returns `None` for
    /// unsupported operators or an unparseable version — callers treat that
    /// as "matches nothing" rather than guessing.
    pub fn parse(s: &str) -> Option<Requirement> {
        let s = s.trim();
        // Two-character operators must be tried before their one-character prefixes.
        let (op, rest) = if let Some(r) = s.strip_prefix(">=") {
            (Op::Ge, r)
        } else if let Some(r) = s.strip_prefix("<=") {
            (Op::Le, r)
        } else if let Some(r) = s.strip_prefix("==") {
            (Op::Eq, r)
        } else if let Some(r) = s.strip_prefix("!=") {
            (Op::Ne, r)
        } else if let Some(r) = s.strip_prefix('>') {
            (Op::Gt, r)
        } else if let Some(r) = s.strip_prefix('<') {
            (Op::Lt, r)
        } else {
            return None;
        };
        Some(Requirement {
            op,
            version: Version::parse(rest)?,
        })
    }

    /// Does `version` satisfy this comparator?
    pub fn matches(&self, version: &Version) -> bool {
        match self.op {
            Op::Lt => version < &self.version,
            Op::Le => version <= &self.version,
            Op::Gt => version > &self.version,
            Op::Ge => version >= &self.version,
            Op::Eq => version == &self.version,
            Op::Ne => version != &self.version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("{s:?} should parse"))
    }

    #[test]
    fn parses_forms_semver_cannot() {
        // Every one of these is skipped by semver::Version::parse today.
        for s in [
            "1.0",
            "3.1",
            "2026.6",
            "1!2.0",
            "1.0a1",
            "1.0.post1",
            "1.0.dev3",
            "1.0+local.5",
        ] {
            assert!(Version::parse(s).is_some(), "{s:?} should parse");
        }
    }

    #[test]
    fn rejects_non_versions() {
        for s in [
            "",
            "not-a-version",
            "1.0.x",
            "1..0",
            "1.0-beta-extra-junk!",
            "*",
        ] {
            assert!(Version::parse(s).is_none(), "{s:?} should be rejected");
        }
    }

    #[test]
    fn normalization_variants_are_equal() {
        // Case, separators, spelled-out phases, v prefix, implicit numbers.
        assert_eq!(v("1.0Alpha1"), v("1.0a1"));
        assert_eq!(v("1.0-beta_2"), v("1.0b2"));
        assert_eq!(v("1.0pre1"), v("1.0rc1"));
        assert_eq!(v("1.0preview1"), v("1.0rc1"));
        assert_eq!(v("1.0c1"), v("1.0rc1"));
        assert_eq!(v("v1.0"), v("1.0"));
        assert_eq!(v("1.0a"), v("1.0a0"));
        assert_eq!(v("1.0-1"), v("1.0.post1"));
        assert_eq!(v("1.0rev2"), v("1.0.post2"));
        assert_eq!(v("1.0.dev"), v("1.0.dev0"));
    }

    #[test]
    fn trailing_zeros_are_insignificant() {
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("1"), v("1.0.0.0"));
        assert!(v("1.0.1") > v("1.0"));
    }

    #[test]
    fn epoch_dominates() {
        assert!(v("1!1.0") > v("2.0"));
        assert!(v("1!1.0") < v("2!0.1"));
    }

    #[test]
    fn spec_example_ordering_chain() {
        // The canonical ordering example from the PEP 440 spec, verbatim.
        let chain = [
            "1.0.dev456",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a12.dev456",
            "1.0a12",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0rc1.dev456",
            "1.0rc1",
            "1.0",
            "1.0+abc.5",
            "1.0+abc.7",
            "1.0+5",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.1.dev1",
        ];
        for pair in chain.windows(2) {
            assert!(
                v(pair[0]) < v(pair[1]),
                "{} should sort before {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn local_numeric_segments_outrank_alpha() {
        assert!(v("1.0+ubuntu.1") < v("1.0+1"));
        assert!(v("1.0+abc") < v("1.0+abd"));
        assert!(v("1.0") < v("1.0+anything"));
    }

    #[test]
    fn requirement_matching_osv_shapes() {
        // The two shapes parse_osv_json synthesizes: ">= fixed", "< introduced".
        let fixed = Requirement::parse(">= 1.4.1").unwrap();
        assert!(!fixed.matches(&v("1.4.0")), "below fix is not patched");
        assert!(fixed.matches(&v("1.4.1")), "at fix is patched");
        assert!(fixed.matches(&v("1.5")), "above fix is patched");
        assert!(!fixed.matches(&v("1.4.1rc1")), "rc of the fix predates it");

        let introduced = Requirement::parse("<39.0.0").unwrap();
        assert!(introduced.matches(&v("38.0.4")));
        assert!(!introduced.matches(&v("39.0.0")));
        assert!(!introduced.matches(&v("39.0")), "39.0 == 39.0.0");
    }

    #[test]
    fn requirement_full_operator_set() {
        assert!(Requirement::parse("== 1.0").unwrap().matches(&v("1.0.0")));
        assert!(Requirement::parse("!= 1.0").unwrap().matches(&v("1.0.1")));
        assert!(Requirement::parse("<= 1.0").unwrap().matches(&v("1.0")));
        assert!(Requirement::parse("> 1.0")
            .unwrap()
            .matches(&v("1.0.post1")));
        assert!(
            Requirement::parse("~= 1.0").is_none(),
            "pip-only operator unsupported"
        );
        assert!(Requirement::parse(">= not.a.version").is_none());
    }
}
