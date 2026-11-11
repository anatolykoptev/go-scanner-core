# go-scanner-core

Shared library module. No main. No binaries. Extracted from go-wowa; consumed by go-pentest. go-wowa migration onto it is planned (not done).

## Packages
- `authz/` — allowlist YAML parser, deny-first scope matcher (opt-in `allow_internal` bypass), danger-op confirm gate
- `audit/` — append-only JSONL audit logger with SHA-256 hash chain
- `target/` — host normalization/classification + SSRF hard-block (loopback/RFC1918/link-local/metadata, no override)

Every document is indexed in [docs/INDEX.md](docs/INDEX.md). Contribution rules: [CONTRIBUTING.md](CONTRIBUTING.md).

## Gate

CI (`.github/workflows/preflight.yml`, job `preflight`, Go 1.26) runs `make preflight` and then
golangci-lint v2.12.2 through its action. `make preflight` is: gostall v1.0.0
(`-lockorder -missingunlock -starvation`), `gofmt -l .` must print nothing, `go vet ./...`,
`go build ./...`, `go test ./... -race -count=1`. A docs-only PR (Markdown, `docs/`, licence,
issue and PR templates) skips that job through the `docs-scope` job in the same workflow; that
block is canonical across the fleet and compared byte for byte, so do not edit it here.

## Invariants that are easy to break

- **The hard-block has no configuration knob.** `target.IsBlocked` (loopback, link-local incl.
  cloud metadata, unspecified address, IMDSv6 and Alibaba IMDS) is checked before any allow or
  deny rule in `authz`. The only way past it is `allow_internal: true`, and that still needs an
  explicit allow rule and must surface `Decision.UsedInternalOverride`. Do not add another way.
- **Deny wins, and the default is deny.** A target matching a deny rule is rejected even when an
  allow rule matches; a target matching nothing is rejected; `ParseAllowlist` rejects a scope
  with zero rules. `allow_internal` is a strict bool: the string `"true"` must fail to parse.
- **Fail closed.** `authz.IsDangerous` treats an unparseable or composite (comma list, boolean
  script grammar) profile as dangerous if any token is. Never downgrade "unsure" to "safe".
- **One normalizer.** Hostname normalization lives in `target.NormalizeHostname` (IDNA, and it
  rejects URL-authority and control characters); `authz` must call it, not grow its own.
- **The audit chain is a wire format.** `self_hash` is `sha256(prev_hash || record_json)` and
  rotation carries the chain across segments. Changing the record's fields, their order or the
  hashing breaks verification of every existing log.
- **The library does not resolve DNS.** A hostname that passed `CheckTarget` can resolve to a
  blocked address later; callers re-check the resolved IP at the dial site. Do not imply otherwise
  in docs or doc comments.
- Fuzz targets are `FuzzParseAllowlist` (`authz/fuzz_test.go`) and `FuzzNormalize`
  (`target/fuzz_test.go`, corpus in `target/testdata/fuzz`); keep the corpus when touching the
  parsers. Versions come from release-please: never tag or edit `CHANGELOG.md` or
  `.release-please-manifest.json` by hand.
- **This repository is public.** No hostnames, operator paths, account names, tokens or
  personal data in any tracked file, tests and fixtures included.
