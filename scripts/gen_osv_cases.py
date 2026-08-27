#!/usr/bin/env python3
"""Generate differential test cases for `tests/osv_corpus.rs` from a real OSV export.

This is deliberately an *independent* implementation of the OSV range semantics,
written from the schema rather than from the Rust code, so that agreement
between the two is evidence rather than a shared assumption. For PyPI it uses
pip's own `packaging.version` (the PEP 440 reference implementation), which
checks the crate's from-scratch comparator against upstream instead of itself.

Usage:

    curl -O https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip
    unzip -q all.zip -d /tmp/osv-crates
    python3 scripts/gen_osv_cases.py /tmp/osv-crates /tmp/osv-cases.json crates.io

    LENS3329_OSV_CORPUS=/tmp/osv-crates \
    LENS3329_OSV_CASES=/tmp/osv-cases.json \
      cargo test --release --test osv_corpus -- --nocapture

Ecosystem is one of: crates.io (default), PyPI, npm.
PyPI requires `packaging` (`pip install packaging`).

For each affected package the script probes every range boundary and the
versions immediately either side of it, since off-by-one at a boundary is the
failure mode that matters and the one hand-written fixtures never catch.
"""

import collections
import glob
import json
import re
import sys

# --------------------------------------------------------------------------
# Version comparison, per ecosystem
# --------------------------------------------------------------------------

_SEMVER = re.compile(
    r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?\Z"
)


def _semver(s):
    """Parse semver into a comparable tuple; None if outside the scheme."""
    m = _SEMVER.match(s)
    if not m:
        return None
    major, minor, patch, pre = int(m[1]), int(m[2]), int(m[3]), m[4]
    if pre is None:
        return (major, minor, patch, 1, ())  # a release sorts after its prereleases
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (major, minor, patch, 0, ids)


def _pep440(s):
    from packaging.version import InvalidVersion, Version

    try:
        return Version(s)
    except InvalidVersion:
        return None


def normalize_pypi(name):
    """PEP 503 normalization, exactly as published."""
    return re.sub(r"[-_.]+", "-", name).lower()


# --------------------------------------------------------------------------
# OSV semantics
# --------------------------------------------------------------------------

ZERO_SENTINELS = ("0", "0.0.0", "0.0.0-0")


def _within(v, lo, hi, hi_inclusive, parse):
    if v is None:
        return False
    if lo is not None:
        low = parse(lo)
        if low is None or v < low:
            return False
    if hi is not None:
        high = parse(hi)
        if high is None:
            return False
        if v > high or (v == high and not hi_inclusive):
            return False
    return True


def affected_by(entry, version, parse):
    """Does a single OSV `affected` entry cover `version`?"""
    v = parse(version)

    for listed in entry.get("versions") or []:
        if listed == version:
            return True
        pl = parse(listed)
        if pl is not None and v is not None and pl == v:
            return True

    ranges = entry.get("ranges") or []
    non_git = [r for r in ranges if r.get("type") != "GIT"]

    # No version qualification at all => the whole package is affected.
    if not ranges and not (entry.get("versions") or []):
        return True
    # GIT ranges bound by commit, which says nothing about released versions.
    # Unevaluable, so it must contribute no matches.
    if ranges and not non_git:
        return False

    for r in non_git:
        low = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                low = None if ev["introduced"] in ZERO_SENTINELS else ev["introduced"]
            if "fixed" in ev:
                if _within(v, low, ev["fixed"], False, parse):
                    return True
                low = None
            if "last_affected" in ev:
                if _within(v, low, ev["last_affected"], True, parse):
                    return True
                low = None
        # A span left open at the end of the event list runs to infinity.
        if low is not None and _within(v, low, None, False, parse):
            return True
    return False


def bump(s, index, delta, parse):
    """Nudge one release component, to probe just either side of a boundary."""
    v = parse(s)
    if v is None:
        return None
    # `packaging.Version` exposes `.release`; the semver tuple is indexable.
    release = list(v.release[:3]) if hasattr(v, "release") else list(v[:3])
    while len(release) < 3:
        release.append(0)
    release[index] += delta
    if release[index] < 0:
        return None
    return f"{release[0]}.{release[1]}.{release[2]}"


def main():
    if len(sys.argv) < 3:
        sys.exit(f"usage: {sys.argv[0]} <corpus-dir> <out.json> [ecosystem]")
    corpus, out = sys.argv[1], sys.argv[2]
    ecosystem = sys.argv[3] if len(sys.argv) > 3 else "crates.io"

    if ecosystem == "PyPI":
        parse, rename = _pep440, normalize_pypi
    else:
        parse, rename = _semver, (lambda n: n)

    cases = []
    tally = collections.Counter()

    for path in sorted(glob.glob(f"{corpus}/**/*.json", recursive=True)):
        try:
            doc = json.load(open(path))
        except (json.JSONDecodeError, OSError):
            tally["unreadable"] += 1
            continue
        advisory_id = doc.get("id")

        # One advisory may carry several `affected` entries for the SAME
        # package, each with its own range. The advisory affects a version if
        # ANY of them does, so expectations must be aggregated per package
        # rather than evaluated per entry.
        by_package = collections.defaultdict(list)
        for entry in doc.get("affected", []):
            pkg = (entry.get("package") or {}).get("name")
            eco = (entry.get("package") or {}).get("ecosystem") or ""
            # A single advisory often spans crates.io, npm, PyPI, Go and NuGet;
            # keep only the ecosystem this export is for.
            if pkg and eco.split(":")[0] == ecosystem:
                by_package[pkg].append(entry)

        for pkg, entries in by_package.items():
            probes = set()
            for entry in entries:
                for r in entry.get("ranges") or []:
                    if r.get("type") == "GIT":
                        continue
                    for ev in r.get("events", []):
                        for key in ("introduced", "fixed", "last_affected"):
                            bound = ev.get(key)
                            if bound and bound not in ZERO_SENTINELS:
                                probes.add(bound)
                                for index in (2, 1):
                                    for delta in (-1, 1):
                                        nudged = bump(bound, index, delta, parse)
                                        if nudged:
                                            probes.add(nudged)
                for listed in (entry.get("versions") or [])[:3]:
                    probes.add(listed)

            for version in sorted(probes):
                if parse(version) is None:
                    continue
                expected = any(affected_by(e, version, parse) for e in entries)
                cases.append(
                    {
                        "advisory": advisory_id,
                        "ecosystem": ecosystem,
                        "package": rename(pkg),
                        "version": version,
                        "expected": expected,
                    }
                )
                tally[expected] += 1

    with open(out, "w") as fh:
        json.dump(cases, fh)
    print(
        f"generated {len(cases)} {ecosystem} cases "
        f"(affected={tally[True]}, clean={tally[False]}, unreadable={tally['unreadable']})"
    )


if __name__ == "__main__":
    main()
