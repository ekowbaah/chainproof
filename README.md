# chainproof
Software-supply-chain verification CLI in Rust. It computes and verifies SHA-256 artifact digests, recognizes SPDX and CycloneDX JSON documents, summarizes their package contents, and evaluates minimum SBOM, provenance, and signing policy.

```bash
cargo run -- artifact.tar
cargo run -- artifact.tar EXPECTED_DIGEST
cargo run -- sbom bom.json
```

Planned adapters cover schema-level SBOM validation, Sigstore bundles, SLSA provenance, SARIF, policy files, and container metadata. A matching digest proves integrity against an expected value; it does not establish artifact identity without a trusted signature or provenance statement.
