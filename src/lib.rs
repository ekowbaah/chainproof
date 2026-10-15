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
    DisallowedLicense(String),
    MutableActionReference(String),
    ExcessiveWorkflowPermission(String),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceSummary {
    pub predicate_type: String,
    pub subject_names: Vec<String>,
    pub builder_id: Option<String>,
}
pub fn inspect_provenance(input: &[u8]) -> Result<ProvenanceSummary, SbomError> {
    let value: Value = serde_json::from_slice(input).map_err(|_| SbomError::InvalidJson)?;
    let predicate_type = value
        .get("predicateType")
        .and_then(Value::as_str)
        .ok_or(SbomError::UnsupportedFormat)?
        .to_owned();
    let subject_names = value
        .get("subject")
        .and_then(Value::as_array)
        .ok_or(SbomError::MissingComponents)?
        .iter()
        .filter_map(|v| v.get("name")?.as_str().map(str::to_owned))
        .collect();
    let builder_id = value
        .pointer("/predicate/builder/id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(ProvenanceSummary {
        predicate_type,
        subject_names,
        builder_id,
    })
}

/// Finds common supply-chain hazards in GitHub Actions without needing a YAML engine.
pub fn inspect_workflow(input: &str) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    for line in input.lines().map(str::trim) {
        if let Some(action) = line.strip_prefix("- uses:").map(str::trim) {
            let reference = action.rsplit_once('@').map(|(_, r)| r).unwrap_or("");
            let pinned = reference.len() == 40 && reference.bytes().all(|c| c.is_ascii_hexdigit());
            if !pinned {
                findings.push(PolicyFinding::MutableActionReference(action.to_owned()));
            }
        }
        if matches!(
            line,
            "contents: write" | "actions: write" | "packages: write"
        ) {
            findings.push(PolicyFinding::ExcessiveWorkflowPermission(line.to_owned()));
        }
    }
    findings
}

pub fn sarif(findings: &[PolicyFinding]) -> Value {
    let results:Vec<Value>=findings.iter().enumerate().map(|(index,finding)|serde_json::json!({"ruleId":format!("chainproof/{index}"),"level":"error","message":{"text":format!("{finding:?}")}})).collect();
    serde_json::json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"chainproof"}},"results":results}]})
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
    #[test]
    fn reads_slsa_provenance_subjects() {
        let p=inspect_provenance(br#"{"predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"image"}],"predicate":{"builder":{"id":"github"}}}"#).unwrap();
        assert_eq!(p.subject_names, vec!["image"]);
        assert_eq!(p.builder_id.as_deref(), Some("github"));
    }
    #[test]
    fn flags_mutable_actions_and_write_permissions() {
        let findings =
            inspect_workflow("- uses: actions/checkout@v4\npermissions:\n  contents: write");
        assert_eq!(findings.len(), 2);
        assert_eq!(
            sarif(&findings)["runs"][0]["results"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
