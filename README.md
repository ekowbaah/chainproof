# chainproof

A small Rust toolkit for checking release artifacts and CI configuration.

It can:

- compute and verify SHA-256 digests
- inspect CycloneDX and SPDX JSON documents
- read subjects and builders from SLSA provenance
- flag mutable GitHub Action references and broad write permissions
- turn findings into SARIF

The CLI currently exposes digest verification and SBOM inspection:

```sh
cargo run -- artifact.tar
cargo run -- artifact.tar EXPECTED_SHA256
cargo run -- sbom bom.json
```

```sh
cargo test
```

A matching digest proves that bytes match an expected value. It does not prove who produced them.
