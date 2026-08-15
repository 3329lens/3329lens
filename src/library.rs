//! Scan-result data types shared between the scanner and its consumers
//! (CLI, dashboards). Moved here from the scanner_dashboard UI module so the
//! scanner crate has no dependency on UI code; presentation-only helpers
//! (`icon`, `name`, `label`) are plain strings and carry no UI framework types.

use serde::{Serialize, Serializer};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize)]
pub struct LibraryInfo {
    pub name: String,
    pub path: PathBuf,
    pub category: LibraryCategory,
    pub library_type: LibraryType,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub size: u64,
    #[serde(serialize_with = "serialize_system_time")]
    pub modified: SystemTime,

    // Risk assessment
    pub risk_level: RiskLevel,
    pub quantum_vulnerable: bool,
}

// Custom serializer for SystemTime
fn serialize_system_time<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use chrono::{DateTime, Utc};
    let datetime = DateTime::<Utc>::from(*time);
    serializer.serialize_str(&datetime.to_rfc3339())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum LibraryCategory {
    SslTls,
    GeneralCrypto,
    PostQuantum,
    HashFunction,
    RustCrypto,
    NodeCrypto,
    PythonCrypto,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum LibraryType {
    SharedLibrary,  // .so, .dll, .dylib
    StaticLibrary,  // .a
    Manifest,       // Cargo.toml, package.json, requirements.txt
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum RiskLevel {
    None,       // PQ-ready, no quantum risk
    Low,        // Hash functions only
    Medium,     // ECDH/ECDSA (some quantum resistance)
    High,       // RSA/DSA (no quantum resistance)
    Critical,   // Legacy algorithms (MD5, DES)
}

impl LibraryCategory {
    pub fn icon(&self) -> &'static str {
        match self {
            LibraryCategory::SslTls => "🔐",
            LibraryCategory::GeneralCrypto => "🔒",
            LibraryCategory::PostQuantum => "⚛️",
            LibraryCategory::HashFunction => "#️⃣",
            LibraryCategory::RustCrypto => "🦀",
            LibraryCategory::NodeCrypto => "📦",
            LibraryCategory::PythonCrypto => "🐍",
            LibraryCategory::Other => "📚",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            LibraryCategory::SslTls => "SSL/TLS",
            LibraryCategory::GeneralCrypto => "General Crypto",
            LibraryCategory::PostQuantum => "Post-Quantum",
            LibraryCategory::HashFunction => "Hash Function",
            LibraryCategory::RustCrypto => "Rust Crypto",
            LibraryCategory::NodeCrypto => "Node.js Crypto",
            LibraryCategory::PythonCrypto => "Python Crypto",
            LibraryCategory::Other => "Other",
        }
    }
}

impl RiskLevel {
    pub fn icon(&self) -> &'static str {
        match self {
            RiskLevel::None => "✅",
            RiskLevel::Low => "ℹ️",
            RiskLevel::Medium => "⚠",
            RiskLevel::High => "⚠️",
            RiskLevel::Critical => "🚨",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::None => "None",
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }
}
