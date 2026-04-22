# go-scanner-core

Shared library module. No main. No binaries. Imported by go-pentest and go-wowa.

## Packages
- `authz/` — allowlist YAML parser, scope matcher, danger-op table
- `audit/` — append-only JSONL audit logger with SHA-256 hash chain
- `target/` — host normalization and classification
