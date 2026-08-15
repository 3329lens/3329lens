/*
 * CycloneDX CBOM (Cryptographic Bill of Materials) Module - Defensive Security
 *
 * Serde data model for emitting CycloneDX 1.6 documents from scanner findings.
 * This is a *subset* of the CycloneDX 1.6 spec, scoped to what the cryptographic
 * library scanner can populate:
 *   - `library` components (one per detected library / dependency)
 *   - `cryptographic-asset` components (algorithms inferred from library identity)
 *   - dependency links between libraries and the algorithms they imply
 *
 * Spec reference: https://cyclonedx.org/docs/1.6/json/
 *
 * NOTE (scaffold): These structs define the output shape only. The conversion
 * from `scanner::CryptoFinding` and the algorithm-inference table are not yet
 * implemented (Phase A/B). Nothing in the binary constructs a `Bom` yet, hence
 * the module-level `dead_code` allowance.
 *
 * Part of the Slow Lynx Cryptography Discovery project.
 */

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::scanner::{CryptoFinding, CryptoType, Ecosystem};

/// Top-level CycloneDX BOM document.
///
/// Serializes to the envelope expected by CycloneDX 1.6 tooling, e.g.:
/// ```jsonc
/// { "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, ... }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    /// Always the literal string "CycloneDX".
    pub bom_format: String,
    /// CycloneDX spec version this document targets (e.g. "1.6").
    pub spec_version: String,
    /// Optional unique identifier, conventionally `urn:uuid:<uuid>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Revision of this BOM for the given serial number (starts at 1).
    pub version: u32,
    pub metadata: Metadata,
    /// Inventory: `library` and `cryptographic-asset` components.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
    /// Links between components (library -> algorithms it implies).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
    /// Known vulnerabilities affecting components, from advisory correlation.
    /// Empty (and omitted) unless a `--advisory-db` was supplied.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<Vulnerability>,
}

impl Bom {
    /// Create an empty BOM envelope for a scan of `target`.
    ///
    /// Populates `bomFormat`, `specVersion`, `version`, and a `metadata` block
    /// with the current timestamp and this tool's identity. Components and
    /// dependencies start empty and are filled by the (future) converter.
    pub fn new(target: &str) -> Self {
        Self {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            serial_number: None,
            version: 1,
            metadata: Metadata::for_target(target),
            components: Vec::new(),
            dependencies: Vec::new(),
            vulnerabilities: Vec::new(),
        }
    }

    /// The `bom-ref` of the `library` component matching `name`/`version`, if
    /// present. Used to link a vulnerability to the component it affects.
    pub fn library_ref(&self, name: &str, version: Option<&str>) -> Option<String> {
        self.components
            .iter()
            .find(|c| {
                c.component_type == ComponentType::Library
                    && c.name == name
                    && c.version.as_deref() == version
            })
            .and_then(|c| c.bom_ref.clone())
    }
}

/// BOM metadata: when it was produced, by what, and about what.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// ISO 8601 / RFC 3339 timestamp of BOM creation.
    pub timestamp: String,
    /// Tools that produced this BOM.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Tool>,
    /// The subject of the BOM (the scanned target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<Component>,
}

impl Metadata {
    fn for_target(target: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tools: vec![Tool {
                name: "slow_lynx".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }],
            component: Some(Component {
                component_type: ComponentType::Application,
                bom_ref: None,
                name: target.to_string(),
                version: None,
                purl: None,
                evidence: None,
                crypto_properties: None,
            }),
        }
    }
}

/// A tool that generated the BOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A CycloneDX component. Used for the scanned application, detected
/// `library` entries, and `cryptographic-asset` entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: ComponentType,
    /// Stable reference used as the target of `dependencies` links.
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Package URL, e.g. `pkg:cargo/ring@0.17`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// Where the component was observed (file locations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    /// Present only for `cryptographic-asset` components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CryptoProperties>,
}

/// CycloneDX component types relevant to this scanner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentType {
    Application,
    Library,
    CryptographicAsset,
}

/// Evidence of where/how a component was detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<Occurrence>,
}

/// A single observed location of a component (e.g. a file path).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Occurrence {
    pub location: String,
}

/// Cryptographic properties for a `cryptographic-asset` component.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    pub asset_type: AssetType,
    /// Present when `assetType == algorithm`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    /// ASN.1 object identifier, when known (e.g. RSA = 1.2.840.113549.1.1.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

/// The kind of cryptographic asset a component represents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AssetType {
    Algorithm,
    Certificate,
    Protocol,
    RelatedCryptoMaterial,
}

/// Properties describing a cryptographic algorithm asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    /// Cryptographic primitive class (kem, signature, pke, hash, ...).
    pub primitive: Primitive,
    /// Parameter set / key size identifier, e.g. "2048", "256", "ML-KEM-768".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    /// Named elliptic curve, when applicable (e.g. "P-256", "Curve25519").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// Classical security strength in bits (e.g. RSA-2048 -> 112).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classical_security_level: Option<u32>,
    /// NIST PQC security level. 0 indicates no quantum resistance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nist_quantum_security_level: Option<u32>,
}

/// CycloneDX cryptographic primitive classes (1.6 subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Primitive {
    /// Key encapsulation mechanism (e.g. ML-KEM / Kyber).
    Kem,
    /// Digital signature (e.g. ECDSA, ML-DSA / Dilithium).
    Signature,
    /// Public-key encryption (e.g. RSA encryption).
    Pke,
    /// Key agreement (e.g. ECDH, X25519).
    KeyAgree,
    /// Block cipher (e.g. AES).
    BlockCipher,
    /// Stream cipher (e.g. ChaCha20).
    StreamCipher,
    /// Hash function (e.g. SHA-256, SHA-3).
    Hash,
    /// Message authentication code (e.g. HMAC, Poly1305).
    Mac,
    /// Key derivation function (e.g. HKDF, Argon2).
    Kdf,
    /// Deterministic random bit generator / CSPRNG.
    Drbg,
    /// Anything not classifiable into the above.
    Other,
}

/// A dependency relationship between components, keyed by `bom-ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    /// The `bom-ref` of the dependent component.
    #[serde(rename = "ref")]
    pub bom_ref: String,
    /// `bom-ref`s this component depends on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

/// A vulnerability affecting one or more components (CycloneDX 1.6
/// `vulnerabilities[]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    /// Advisory identifier, e.g. `RUSTSEC-2023-0001`.
    pub id: String,
    /// Severity/score ratings for this vulnerability.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ratings: Vec<Rating>,
    /// Human-readable description / title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `bom-ref`s of the components this vulnerability affects.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub affects: Vec<Affects>,
}

/// A severity rating for a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rating {
    /// CVSS base score, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Qualitative severity (critical/high/medium/low/none).
    pub severity: String,
    /// Scoring method, e.g. "CVSSv3".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Reference to a component affected by a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affects {
    #[serde(rename = "ref")]
    pub bom_ref: String,
}

/// Build a CycloneDX 1.6 CBOM from scanner findings.
///
/// Emits two kinds of components:
///   - `library`: one per unique (ecosystem, name, version), with every
///     detection location recorded as an `evidence.occurrences` entry and a
///     synthesized purl for known ecosystems (binary libraries carry no purl).
///   - `cryptographic-asset`: algorithms *inferred* from each library's
///     identity (see [`algorithms_for_library`]), de-duplicated so a shared
///     algorithm (e.g. SHA-256) is a single component referenced by many libs.
///
/// Libraries are linked to the algorithms they imply via `dependencies`.
///
/// IMPORTANT: algorithm assets are inferred from library *identity*, not from
/// observed runtime calls. This is a teaching-grade CBOM: presence of an
/// algorithm asset means "this library can do X", not "X is actually invoked".
pub fn findings_to_cbom(findings: &[CryptoFinding], target: &str) -> Bom {
    let mut bom = Bom::new(target);
    // (ecosystem, name, version) -> index of the library component.
    let mut lib_index: HashMap<String, usize> = HashMap::new();
    // algorithm bom-ref -> already emitted as a component (dedup across libs).
    let mut algo_emitted: HashSet<String> = HashSet::new();
    // library bom-ref -> index into `deps`.
    let mut dep_index: HashMap<String, usize> = HashMap::new();
    let mut deps: Vec<Dependency> = Vec::new();

    for finding in findings {
        // --- library component (one per unique ecosystem/name/version) ---
        let version = finding.version.clone();
        let lib_key = format!(
            "{:?}|{}|{}",
            finding.ecosystem,
            finding.name,
            version.as_deref().unwrap_or("")
        );

        let lib_idx = *lib_index.entry(lib_key).or_insert_with(|| {
            let purl = build_purl(&finding.ecosystem, &finding.name, version.as_deref());
            let bom_ref = purl
                .clone()
                .unwrap_or_else(|| format!("lib/{}", finding.name));
            bom.components.push(Component {
                component_type: ComponentType::Library,
                bom_ref: Some(bom_ref),
                name: finding.name.clone(),
                version: version.clone(),
                purl,
                evidence: Some(Evidence {
                    occurrences: Vec::new(),
                }),
                crypto_properties: None,
            });
            bom.components.len() - 1
        });

        // Record this detection location, de-duplicating repeats.
        if let Some(evidence) = bom.components[lib_idx].evidence.as_mut() {
            if !evidence.occurrences.iter().any(|o| o.location == finding.path) {
                evidence.occurrences.push(Occurrence {
                    location: finding.path.clone(),
                });
            }
        }

        let lib_ref = bom.components[lib_idx]
            .bom_ref
            .clone()
            .expect("library components always carry a bom-ref");

        // --- inferred algorithm assets + dependency links ---
        for spec in algorithms_for_library(&finding.name) {
            let algo_ref = format!("crypto/algorithm/{}", slug(spec.name));

            // Emit the algorithm component once, shared across libraries.
            if algo_emitted.insert(algo_ref.clone()) {
                bom.components.push(Component {
                    component_type: ComponentType::CryptographicAsset,
                    bom_ref: Some(algo_ref.clone()),
                    name: spec.name.to_string(),
                    version: None,
                    purl: None,
                    evidence: None,
                    crypto_properties: Some(CryptoProperties {
                        asset_type: AssetType::Algorithm,
                        algorithm_properties: Some(AlgorithmProperties {
                            primitive: spec.primitive.clone(),
                            parameter_set_identifier: spec.parameter_set.map(str::to_string),
                            curve: spec.curve.map(str::to_string),
                            classical_security_level: spec.classical_security_level,
                            nist_quantum_security_level: spec.nist_quantum_security_level,
                        }),
                        oid: spec.oid.map(str::to_string),
                    }),
                });
            }

            // Link this library to the algorithm it implies.
            add_dependency(&mut deps, &mut dep_index, &lib_ref, algo_ref);
        }

        // --- SSL/TLS libraries additionally expose the TLS protocol ---
        if finding.crypto_type == CryptoType::SSL_TLS {
            let proto_ref = "crypto/protocol/tls".to_string();
            if algo_emitted.insert(proto_ref.clone()) {
                bom.components.push(Component {
                    component_type: ComponentType::CryptographicAsset,
                    bom_ref: Some(proto_ref.clone()),
                    name: "TLS".to_string(),
                    version: None,
                    purl: None,
                    evidence: None,
                    crypto_properties: Some(CryptoProperties {
                        asset_type: AssetType::Protocol,
                        algorithm_properties: None,
                        oid: None,
                    }),
                });
            }
            add_dependency(&mut deps, &mut dep_index, &lib_ref, proto_ref);
        }
    }

    bom.dependencies = deps;
    bom
}

/// Append `target_ref` to the dependency entry for `lib_ref`, creating the
/// entry if needed and de-duplicating repeated links.
fn add_dependency(
    deps: &mut Vec<Dependency>,
    dep_index: &mut HashMap<String, usize>,
    lib_ref: &str,
    target_ref: String,
) {
    let idx = *dep_index.entry(lib_ref.to_string()).or_insert_with(|| {
        deps.push(Dependency {
            bom_ref: lib_ref.to_string(),
            depends_on: Vec::new(),
        });
        deps.len() - 1
    });
    if !deps[idx].depends_on.contains(&target_ref) {
        deps[idx].depends_on.push(target_ref);
    }
}

/// Synthesize a Package URL (purl) for a finding, when its ecosystem has one.
/// Binary/static libraries on disk (`System`) have no package coordinate.
fn build_purl(ecosystem: &Ecosystem, name: &str, version: Option<&str>) -> Option<String> {
    let kind = match ecosystem {
        Ecosystem::Cargo => "cargo",
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::System => return None,
    };
    // Scoped npm names (`@scope/pkg`) encode the leading `@` as `%40` per the
    // purl spec; the namespace separator `/` stays literal.
    let encoded_name = if *ecosystem == Ecosystem::Npm {
        if let Some(rest) = name.strip_prefix('@') {
            format!("%40{}", rest)
        } else {
            name.to_string()
        }
    } else {
        name.to_string()
    };
    let version_suffix = version.map(|v| format!("@{}", v)).unwrap_or_default();
    Some(format!("pkg:{}/{}{}", kind, encoded_name, version_suffix))
}

/// Format 16 random bytes as an RFC 4122 version-4 UUID string (no `urn:uuid:`
/// prefix). The caller supplies entropy — Slow Lynx uses its own CSPRNG — so
/// this stays a pure, testable transform. Sets the version (4) and variant bits.
pub fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// A cryptographic algorithm asset inferred from a library's identity.
struct AlgorithmSpec {
    name: &'static str,
    primitive: Primitive,
    parameter_set: Option<&'static str>,
    curve: Option<&'static str>,
    classical_security_level: Option<u32>,
    /// NIST PQC security category. `Some(0)` flags a Shor-breakable asymmetric
    /// algorithm; symmetric/hash use their residual category; `None` where the
    /// notion does not cleanly apply (e.g. KDFs).
    nist_quantum_security_level: Option<u32>,
    oid: Option<&'static str>,
}

#[allow(clippy::too_many_arguments)]
fn algo(
    name: &'static str,
    primitive: Primitive,
    parameter_set: Option<&'static str>,
    curve: Option<&'static str>,
    classical_security_level: Option<u32>,
    nist_quantum_security_level: Option<u32>,
    oid: Option<&'static str>,
) -> AlgorithmSpec {
    AlgorithmSpec {
        name,
        primitive,
        parameter_set,
        curve,
        classical_security_level,
        nist_quantum_security_level,
        oid,
    }
}

// Reusable specs for algorithms shared across many libraries. The Shor-breakable
// asymmetric algorithms carry nistQuantumSecurityLevel = 0.
fn rsa() -> AlgorithmSpec {
    algo("RSA-2048", Primitive::Pke, Some("2048"), None, Some(112), Some(0), Some("1.2.840.113549.1.1.1"))
}
fn ecdsa() -> AlgorithmSpec {
    algo("ECDSA-P256", Primitive::Signature, Some("P-256"), Some("P-256"), Some(128), Some(0), Some("1.2.840.10045.2.1"))
}
fn ecdh() -> AlgorithmSpec {
    algo("ECDH-P256", Primitive::KeyAgree, Some("P-256"), Some("P-256"), Some(128), Some(0), None)
}
fn ed25519() -> AlgorithmSpec {
    algo("Ed25519", Primitive::Signature, None, Some("Curve25519"), Some(128), Some(0), Some("1.3.101.112"))
}
fn x25519() -> AlgorithmSpec {
    algo("X25519", Primitive::KeyAgree, None, Some("Curve25519"), Some(128), Some(0), Some("1.3.101.110"))
}
fn aes256() -> AlgorithmSpec {
    algo("AES-256", Primitive::BlockCipher, Some("256"), None, Some(256), Some(5), Some("2.16.840.1.101.3.4.1"))
}
fn chacha20() -> AlgorithmSpec {
    algo("ChaCha20", Primitive::StreamCipher, Some("256"), None, Some(256), Some(5), None)
}
fn poly1305() -> AlgorithmSpec {
    algo("Poly1305", Primitive::Mac, None, None, Some(128), Some(5), None)
}
fn sha256() -> AlgorithmSpec {
    algo("SHA-256", Primitive::Hash, Some("256"), None, Some(128), Some(2), Some("2.16.840.1.101.3.4.2.1"))
}
fn hmac() -> AlgorithmSpec {
    algo("HMAC", Primitive::Mac, None, None, None, None, None)
}
fn mlkem768() -> AlgorithmSpec {
    algo("ML-KEM-768", Primitive::Kem, Some("ML-KEM-768"), None, None, Some(3), None)
}
fn mldsa65() -> AlgorithmSpec {
    algo("ML-DSA-65", Primitive::Signature, Some("ML-DSA-65"), None, None, Some(3), None)
}

/// Infer the cryptographic algorithms a library is capable of, from its name.
///
/// Umbrella libraries (OpenSSL, ring, rustls, libsodium, ...) map to a
/// representative set; single-primitive crates map to one algorithm. Unknown
/// libraries return an empty set rather than fabricating assets.
fn algorithms_for_library(name: &str) -> Vec<AlgorithmSpec> {
    let n = name.to_lowercase();

    // Post-quantum: umbrella crates/libs, then specific primitives.
    if n.contains("oqs") || n.contains("pqcrypto") {
        return vec![mlkem768(), mldsa65()];
    }
    if n.contains("kyber") {
        return vec![mlkem768()];
    }
    if n.contains("dilithium") {
        return vec![mldsa65()];
    }
    if n.contains("falcon") {
        return vec![algo("Falcon-512", Primitive::Signature, Some("Falcon-512"), None, None, Some(1), None)];
    }
    if n.contains("sphincs") {
        return vec![algo("SLH-DSA (SPHINCS+)", Primitive::Signature, Some("SPHINCS+-128s"), None, None, Some(1), None)];
    }

    // SSL/TLS umbrella libraries.
    if n.contains("openssl")
        || n.contains("libssl")
        || n.contains("libcrypto")
        || n.contains("boringssl")
        || n.contains("libressl")
        || n.contains("mbedtls")
        || n.contains("wolfssl")
    {
        return vec![rsa(), ecdsa(), ecdh(), aes256(), sha256()];
    }
    if n.contains("rustls") {
        return vec![x25519(), ecdsa(), aes256(), chacha20(), sha256()];
    }

    // General-purpose umbrella libraries.
    if n.contains("sodium") || n == "nacl" || n.contains("tweetnacl") {
        return vec![x25519(), ed25519(), chacha20(), poly1305()];
    }
    if n == "ring" {
        return vec![ed25519(), x25519(), aes256(), chacha20(), sha256(), hmac()];
    }
    if n.contains("bouncycastle")
        || n.contains("cryptopp")
        || n.contains("libgcrypt")
        || n.contains("node-forge")
        || n.contains("crypto-js")
        || n.contains("cryptography")
        || n.contains("pycryptodome")
    {
        return vec![rsa(), aes256(), sha256()];
    }

    // Single-primitive crates. Order matters: check ECDSA/ECDH before "dsa".
    if n.contains("ed25519") {
        return vec![ed25519()];
    }
    if n.contains("x25519") {
        return vec![x25519()];
    }
    if n.contains("ecdsa") || n.contains("ecc") {
        return vec![ecdsa()];
    }
    if n.contains("ecdh") {
        return vec![ecdh()];
    }
    if n == "rsa" {
        return vec![rsa()];
    }
    if n.contains("dsa") {
        return vec![algo("DSA", Primitive::Signature, None, None, Some(112), Some(0), Some("1.2.840.10040.4.1"))];
    }
    if n.contains("chacha20") {
        return vec![chacha20()];
    }
    if n.contains("aes") {
        return vec![aes256()];
    }
    if n.contains("sha3") {
        return vec![sha256_variant("SHA3-256")];
    }
    if n.contains("sha2") {
        return vec![sha256()];
    }
    if n.contains("blake2") {
        return vec![algo("BLAKE2", Primitive::Hash, None, None, Some(128), Some(2), None)];
    }
    if n.contains("blake3") {
        return vec![algo("BLAKE3", Primitive::Hash, None, None, Some(128), Some(2), None)];
    }
    if n.contains("argon2") {
        return vec![algo("Argon2", Primitive::Kdf, None, None, None, None, None)];
    }
    if n.contains("bcrypt") {
        return vec![algo("bcrypt", Primitive::Kdf, None, None, None, None, None)];
    }
    if n.contains("hashlib") {
        return vec![sha256()];
    }

    // Unknown library: do not fabricate algorithm assets.
    Vec::new()
}

/// A SHA-2-family hash with a different display name (e.g. SHA3-256).
fn sha256_variant(name: &'static str) -> AlgorithmSpec {
    algo(name, Primitive::Hash, Some("256"), None, Some(128), Some(2), None)
}

/// Lowercase a name and replace any non-alphanumeric run with single hyphens,
/// for use in stable `bom-ref` identifiers.
fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_hyphen = false;
    for c in s.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
            last_hyphen = false;
        } else if !last_hyphen {
            out.push('-');
            last_hyphen = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{CryptoType, FindingType, VersionSource};
    use std::collections::HashSet;

    fn finding(
        name: &str,
        eco: Ecosystem,
        ctype: CryptoType,
        ver: Option<&str>,
        path: &str,
    ) -> CryptoFinding {
        CryptoFinding {
            path: path.to_string(),
            name: name.to_string(),
            finding_type: FindingType::DependencyManifest,
            crypto_type: ctype,
            ecosystem: eco,
            version: ver.map(str::to_string),
            version_source: VersionSource::Declared,
            details: String::new(),
        }
    }

    #[test]
    fn envelope_is_cyclonedx_1_6() {
        let bom = findings_to_cbom(&[], "target");
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
        assert_eq!(bom.version, 1);
    }

    #[test]
    fn every_dependency_ref_resolves_to_a_component() {
        let findings = vec![
            finding("ring", Ecosystem::Cargo, CryptoType::GeneralCrypto, Some("0.17"), "/p/Cargo.toml"),
            finding("openssl", Ecosystem::Cargo, CryptoType::SSL_TLS, Some("0.10"), "/p/Cargo.toml"),
        ];
        let bom = findings_to_cbom(&findings, "target");
        let refs: HashSet<&str> = bom
            .components
            .iter()
            .filter_map(|c| c.bom_ref.as_deref())
            .collect();
        for dep in &bom.dependencies {
            assert!(refs.contains(dep.bom_ref.as_str()), "dangling ref {}", dep.bom_ref);
            for target in &dep.depends_on {
                assert!(refs.contains(target.as_str()), "dangling dependsOn {}", target);
            }
        }
    }

    #[test]
    fn shared_algorithms_are_deduplicated() {
        // ring and openssl both imply SHA-256 / AES-256.
        let findings = vec![
            finding("ring", Ecosystem::Cargo, CryptoType::GeneralCrypto, None, "/a"),
            finding("openssl", Ecosystem::Cargo, CryptoType::SSL_TLS, None, "/b"),
        ];
        let bom = findings_to_cbom(&findings, "t");
        let sha = bom.components.iter().filter(|c| c.name == "SHA-256").count();
        assert_eq!(sha, 1, "SHA-256 should be a single shared component");
    }

    #[test]
    fn unknown_library_infers_no_algorithms() {
        let findings = vec![finding(
            "totally-unknown-lib",
            Ecosystem::Cargo,
            CryptoType::Unknown,
            None,
            "/a",
        )];
        let bom = findings_to_cbom(&findings, "t");
        let assets = bom
            .components
            .iter()
            .filter(|c| c.component_type == ComponentType::CryptographicAsset)
            .count();
        assert_eq!(assets, 0);
    }

    #[test]
    fn tls_library_emits_protocol_asset() {
        let findings = vec![finding(
            "openssl",
            Ecosystem::System,
            CryptoType::SSL_TLS,
            None,
            "/lib/libssl.so",
        )];
        let bom = findings_to_cbom(&findings, "t");
        let has_tls = bom.components.iter().any(|c| {
            c.component_type == ComponentType::CryptographicAsset
                && c.name == "TLS"
                && matches!(
                    c.crypto_properties.as_ref().map(|p| &p.asset_type),
                    Some(AssetType::Protocol)
                )
        });
        assert!(has_tls, "SSL/TLS library should expose a TLS protocol asset");
    }

    #[test]
    fn purls_only_for_packaged_ecosystems() {
        let findings = vec![
            finding("ring", Ecosystem::Cargo, CryptoType::GeneralCrypto, Some("0.17"), "/a"),
            finding("libssl.so", Ecosystem::System, CryptoType::SSL_TLS, None, "/lib/libssl.so"),
        ];
        let bom = findings_to_cbom(&findings, "t");
        let ring = bom.components.iter().find(|c| c.name == "ring").unwrap();
        assert_eq!(ring.purl.as_deref(), Some("pkg:cargo/ring@0.17"));
        let sys = bom.components.iter().find(|c| c.name == "libssl.so").unwrap();
        assert_eq!(sys.purl, None);
    }

    #[test]
    fn scoped_npm_name_encodes_at_sign_in_purl() {
        let findings = vec![
            finding("@scope/cryptolib", Ecosystem::Npm, CryptoType::GeneralCrypto, Some("2.4.0"), "/p/package.json"),
            finding("node-forge", Ecosystem::Npm, CryptoType::GeneralCrypto, Some("1.3.1"), "/p/package.json"),
        ];
        let bom = findings_to_cbom(&findings, "t");
        let scoped = bom.components.iter().find(|c| c.name == "@scope/cryptolib").unwrap();
        assert_eq!(scoped.purl.as_deref(), Some("pkg:npm/%40scope/cryptolib@2.4.0"));
        let plain = bom.components.iter().find(|c| c.name == "node-forge").unwrap();
        assert_eq!(plain.purl.as_deref(), Some("pkg:npm/node-forge@1.3.1"));
    }

    #[test]
    fn vulnerabilities_omitted_when_empty_and_present_when_populated() {
        // No advisory DB supplied: findings_to_cbom must not emit a key.
        let findings = vec![finding(
            "ring",
            Ecosystem::Cargo,
            CryptoType::GeneralCrypto,
            Some("0.16.0"),
            "/p/Cargo.toml",
        )];
        let mut bom = findings_to_cbom(&findings, "t");
        assert!(bom.vulnerabilities.is_empty());
        let json = serde_json::to_value(&bom).unwrap();
        assert!(json.get("vulnerabilities").is_none(), "key omitted when empty");

        // Populated: links to the affected library's bom-ref and serializes.
        let lib_ref = bom
            .library_ref("ring", Some("0.16.0"))
            .expect("ring library component exists");
        bom.vulnerabilities.push(Vulnerability {
            id: "RUSTSEC-TEST-0001".to_string(),
            ratings: vec![Rating {
                score: Some(9.8),
                severity: "critical".to_string(),
                method: Some("CVSSv3".to_string()),
            }],
            description: Some("test".to_string()),
            affects: vec![Affects { bom_ref: lib_ref.clone() }],
        });
        let json = serde_json::to_value(&bom).unwrap();
        let vulns = json["vulnerabilities"].as_array().expect("array present");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["id"], "RUSTSEC-TEST-0001");
        assert_eq!(vulns[0]["affects"][0]["ref"], serde_json::json!(lib_ref));
        assert_eq!(vulns[0]["ratings"][0]["severity"], "critical");
    }

    #[test]
    fn uuid_v4_has_correct_shape_and_bits() {
        let u = format_uuid_v4([0u8; 16]);
        assert_eq!(u.len(), 36);
        let b = u.as_bytes();
        assert_eq!(b[8], b'-');
        assert_eq!(b[13], b'-');
        assert_eq!(b[18], b'-');
        assert_eq!(b[23], b'-');
        assert_eq!(b[14], b'4', "version nibble must be 4");
        assert!(matches!(b[19], b'8' | b'9' | b'a' | b'b'), "variant bits must be 10xx");
    }

    #[test]
    fn serialized_keys_are_cyclonedx_shaped() {
        let findings = vec![finding(
            "openssl",
            Ecosystem::Cargo,
            CryptoType::SSL_TLS,
            Some("0.10"),
            "/p/Cargo.toml",
        )];
        let bom = findings_to_cbom(&findings, "t");
        let json = serde_json::to_value(&bom).unwrap();
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert_eq!(json["specVersion"], "1.6");
        // A crypto-asset must serialize with camelCase + kebab-case enum values.
        let asset = json["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"] == "cryptographic-asset")
            .expect("expected a cryptographic-asset component");
        assert_eq!(asset["cryptoProperties"]["assetType"], "algorithm");
        assert!(asset["bom-ref"].is_string());
    }
}
