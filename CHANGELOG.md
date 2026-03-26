# Changelog

## v1.0.0 (2026-03-25)

Initial release.

### Features

- **Ed25519 model signing** with domain-prefixed messages (`modelsign-v1:`)
- **Model Identity Card** — structured, signed metadata (architecture, base model, training, eval metrics, provenance)
- **RFC 8785 canonical JSON** for deterministic, cross-platform signature verification
- **Streaming SHA-256** for large model files (1MB chunks, no full-file memory load)
- **Directory support** — sign multi-file models with recursive manifests
- **TOFU keyring** — trust-on-first-use with persistent trusted key store
- **CLI commands**: `sign`, `verify`, `inspect`, `keygen`, `keyring`, `version`
- **Python SDK** — all modules independently importable
- **Response signing middleware** (optional) for API endpoint authenticity
- **Version migration policy** — forward-compatible .sig format with semver checks
