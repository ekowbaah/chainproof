use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};
pub fn digest(bytes: &[u8]) -> String {
    let result = Sha256::digest(bytes);
    result.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn verify_file(path: impl AsRef<Path>, expected: &str) -> io::Result<bool> {
    Ok(digest(&fs::read(path)?) == expected.to_ascii_lowercase())
}
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyFinding {
    MissingSbom,
    MissingProvenance,
    UnsignedArtifact,
    EmptySbom,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomSummary {
    pub format: SbomFormat,
    pub document_name: Option<String>,
    pub component_count: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SbomError {
    InvalidJson,
    UnsupportedFormat,
    MissingComponents,
}
pub fn inspect_sbom(input: &[u8]) -> Result<SbomSummary, SbomError> {
    let value: Value = serde_json::from_slice(input).map_err(|_| SbomError::InvalidJson)?;
    if value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        let components = value
            .get("components")
            .and_then(Value::as_array)
            .ok_or(SbomError::MissingComponents)?;
        return Ok(SbomSummary {
            format: SbomFormat::CycloneDx,
            document_name: value
                .pointer("/metadata/component/name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            component_count: components.len(),
        });
    }
    if value
        .get("spdxVersion")
        .and_then(Value::as_str)
        .is_some_and(|v| v.starts_with("SPDX-"))
    {
        let packages = value
            .get("packages")
            .and_then(Value::as_array)
            .ok_or(SbomError::MissingComponents)?;
        return Ok(SbomSummary {
            format: SbomFormat::Spdx,
            document_name: value.get("name").and_then(Value::as_str).map(str::to_owned),
            component_count: packages.len(),
        });
    }
    Err(SbomError::UnsupportedFormat)
}
pub fn evaluate_policy(
    has_sbom: bool,
    has_provenance: bool,
    is_signed: bool,
) -> Vec<PolicyFinding> {
    let mut f = Vec::new();
    if !has_sbom {
        f.push(PolicyFinding::MissingSbom)
    }
    if !has_provenance {
        f.push(PolicyFinding::MissingProvenance)
    }
    if !is_signed {
        f.push(PolicyFinding::UnsignedArtifact)
    }
    f
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_policy_violations() {
        assert_eq!(
            evaluate_policy(false, true, false),
            vec![PolicyFinding::MissingSbom, PolicyFinding::UnsignedArtifact]
        );
    }
    #[test]
    fn digest_changes() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(digest(b"safe"), digest(b"tampered"));
    }
    #[test]
    fn inspects_cyclonedx() {
        let sbom=br#"{"bomFormat":"CycloneDX","metadata":{"component":{"name":"api"}},"components":[{"name":"serde"}]}"#;
        assert_eq!(
            inspect_sbom(sbom).unwrap(),
            SbomSummary {
                format: SbomFormat::CycloneDx,
                document_name: Some("api".into()),
                component_count: 1
            }
        );
    }
    #[test]
    fn inspects_spdx() {
        let sbom = br#"{"spdxVersion":"SPDX-2.3","name":"service","packages":[{},{}]}"#;
        assert_eq!(inspect_sbom(sbom).unwrap().component_count, 2);
    }
    #[test]
    fn rejects_unknown_or_malformed_sboms() {
        assert_eq!(inspect_sbom(b"nope"), Err(SbomError::InvalidJson));
        assert_eq!(
            inspect_sbom(br#"{"name":"x"}"#),
            Err(SbomError::UnsupportedFormat)
        );
    }
}
