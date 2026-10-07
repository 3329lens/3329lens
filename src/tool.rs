//! Identity of the tool that produced a report.
//!
//! CBOM (`metadata.tools`) and SARIF (`runs[].tool.driver`) output both name
//! the tool that generated them. That is whichever program calls this
//! library, which is not necessarily 3329lens itself, so the identity is a
//! value the caller can supply. [`ToolInfo::default`] is 3329lens's own.

/// Name, version and home page of the tool that produced a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInfo {
    /// Tool name, e.g. `"3329lens"`.
    pub name: String,
    /// Tool version, e.g. `"0.2.1"`.
    pub version: String,
    /// Where to find out about the tool. SARIF requires this; CycloneDX's
    /// `metadata.tools` entry has no field for it, so CBOM output ignores it.
    pub information_uri: String,
}

impl ToolInfo {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        information_uri: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            information_uri: information_uri.into(),
        }
    }
}

impl Default for ToolInfo {
    /// 3329lens, at the version of this crate.
    fn default() -> Self {
        Self::new(
            "3329lens",
            env!("CARGO_PKG_VERSION"),
            "https://github.com/3329lens/3329lens",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_3329lens() {
        let t = ToolInfo::default();
        assert_eq!(t.name, "3329lens");
        assert_eq!(t.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(t.information_uri, "https://github.com/3329lens/3329lens");
    }
}
