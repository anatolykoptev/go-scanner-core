# go-scanner-core

Shared library module. No main. No binaries. Extracted from go-wowa; consumed by go-pentest. go-wowa migration onto it is planned (not done).

## Packages
- `authz/` — allowlist YAML parser, deny-first scope matcher (opt-in `allow_internal` bypass), danger-op confirm gate
- `audit/` — append-only JSONL audit logger with SHA-256 hash chain
- `target/` — host normalization/classification + SSRF hard-block (loopback/RFC1918/link-local/metadata, no override)
