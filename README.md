# chainproof
Software-supply-chain verification CLI in Rust. The MVP computes and verifies deterministic artifact digests and evaluates minimum SBOM, provenance, and signing policy.

```bash
cargo run -- artifact.tar
cargo run -- artifact.tar EXPECTED_DIGEST
```

Planned adapters cover SHA-256, SPDX/CycloneDX, Sigstore bundles, SLSA provenance, SARIF, and container metadata. The custom MVP digest is demonstrative and is **not** a cryptographic signature.
