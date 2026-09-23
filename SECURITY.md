# Security Policy

## Reporting a vulnerability

Please report security issues privately. Do **not** open a public issue.

- **GitHub** — use [private vulnerability reporting](https://github.com/3329lens/3329lens/security/advisories/new)
  on this repository. This is the preferred route: it keeps the report, the fix
  and the advisory in one place.
- **Email** — `security@3329lens.dev`, if you would rather not use GitHub or do
  not have an account.

Please include enough to reproduce: the version of 3329lens, the command you
ran, the input that triggered it (a minimal manifest, lockfile or advisory file
is ideal), and what you expected to happen instead.

### What to expect

| | |
| --- | --- |
| Acknowledgement | Within **3 working days** |
| Initial assessment | Within **10 working days** — whether it is in scope, and a severity |
| Fix or mitigation | Target **90 days** from acknowledgement, sooner for high severity |
| Credit | Offered in the advisory and release notes unless you ask us not to |

`security@3329lens.dev` is a triage address with a person behind it, kept
separate from the `contact@` address published in the crate metadata so that
reports are not buried in registry mail.

We do not operate a paid bug bounty.

## Supported versions

3329lens is pre-1.0. Security fixes are issued for the **latest published
version** only; there are no long-term support branches. Upgrade before
reporting, in case the issue is already fixed.

| Version | Supported |
| --- | --- |
| Latest `0.x` release | ✅ |
| Earlier `0.x` releases | ❌ — upgrade to the latest |

## Scope

This is a scanner. Its security-relevant failure mode is not usually memory
safety — it is **reporting the wrong answer about someone else's security**.
The following are in scope and treated as security issues, not ordinary bugs:

- **Silent false negatives in advisory correlation.** A vulnerable package that
  is not reported, or an advisory range that fails to match a version inside
  it. Users gate their CI on this output, so a miss is a security failure. If
  `--fail-on` passes when it should have failed, that is a vulnerability in
  this tool.
- **An advisory database that loads no advisories without erroring.** A scan
  that reports "nothing matched" because nothing was *loaded* is
  indistinguishable from a clean result. This must always be a hard error.
- **Cross-ecosystem mismatches** — a crates.io advisory matching a same-named
  npm or PyPI package, or vice versa.
- **Path traversal or unintended writes** when walking a scanned tree or
  writing output files.
- **Crashes, hangs or unbounded memory** on untrusted input: hostile manifests,
  lockfiles, or advisory databases.
- **Leaking scanned content** — paths, package inventories or any other data
  about the machine being scanned — off the machine. The scanner is offline by
  design and performs no network access; any network traffic at all is a bug.

Out of scope:

- **False positives**, unless they are systematic. Report them as ordinary
  issues; they waste time but do not create a false sense of safety.
- **Incomplete advisory coverage.** Correlation is only ever as complete as the
  local database you supply, and covers the Cargo, npm and PyPI ecosystems.
  3329lens is not a replacement for `cargo audit`, `npm audit` or `pip-audit`.
- **Algorithm assets inferred from library identity.** A CBOM algorithm
  component means "this library implements X", not "X is invoked at runtime".
  This is documented, deliberate, and teaching-grade.
- Vulnerabilities in the *libraries 3329lens reports on* — those belong to
  their maintainers, and to the advisory databases.

## Disclosure

We follow coordinated disclosure. We will agree a date with you, publish a
GitHub Security Advisory with a CVE where one is warranted, and release the
fixed version at the same time. If a report is already public or being
exploited, we will move faster and say so.
