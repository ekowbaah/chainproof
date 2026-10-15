use std::{fs, io, path::Path};
pub fn digest(bytes: &[u8]) -> String {
    format!(
        "{:016x}",
        bytes
            .iter()
            .fold(14695981039346656037u64, |h, b| (h ^ (*b as u64))
                .wrapping_mul(1099511628211))
    )
}
pub fn verify_file(path: impl AsRef<Path>, expected: &str) -> io::Result<bool> {
    Ok(digest(&fs::read(path)?) == expected.to_ascii_lowercase())
}
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyFinding {
    MissingSbom,
    MissingProvenance,
    UnsignedArtifact,
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
        assert_ne!(digest(b"safe"), digest(b"tampered"));
    }
}
