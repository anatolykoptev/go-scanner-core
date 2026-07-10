# go-scanner-core

Safety primitives for services that take an externally-supplied target and reach out
to it — security scanners, crawlers, URL fetchers. It is the **guardrail** that keeps a
powerful outbound tool from becoming a weapon: against your own infrastructure (SSRF),
against unauthorized targets (scope), and against undetectable misuse (tamper-evident audit).

Extracted from [go-wowa]; currently consumed by go-pentest. No `main`, no binaries — a
library you wire into the authorize/dial path of your own service.

```
go get github.com/anatolykoptev/go-scanner-core@latest
```

## Why a separate library

Any service that "takes a target and connects to it" needs the same three guarantees.
Hand-rolling them per service is exactly how SSRF bugs ship — inconsistent, unreviewed,
per-service. This packages them once, hardened and independently reviewable.

## Packages

### `authz` — "am I allowed to scan this?"

Deny-first allow/deny matching from a YAML allowlist, plus an **unconditional hard-block**
for internal / SSRF-class targets that operator config cannot accidentally widen.

```go
checker, _ := authz.NewChecker(scope) // scope parsed from allowlist YAML

// Internal targets are hard-denied even under a broad allow rule:
checker.CheckTarget("169.254.169.254") // => false (cloud-metadata endpoint)
checker.CheckTarget("127.0.0.1")       // => false (loopback)
checker.CheckTarget("scanme.nmap.org") // => true if in scope

// Audit-aware decision (see the internal-override escape hatch below):
d := checker.CheckTargetDecision(target)
// d.Allowed, d.UsedInternalOverride
```

The hard-block covers loopback, link-local, IPv4/IPv6 cloud-metadata (AWS/Azure/GCP/Oracle
IMDSv4 + IMDSv6, Alibaba), and the unspecified address. RFC1918 private ranges are
allowlist-overridable by design; the hard-blocked set is not — **unless** the allowlist
opts in with `allow_internal: true`, which still requires the internal target to match an
explicit allow rule (it can never open a target by itself) and surfaces
`UsedInternalOverride` so the consumer can audit-log every override.

It also gates dangerous scan operations — `authz.IsDangerous(tool, profile)` fails **closed**
on nmap NSE / nuclei profiles that need explicit `confirm_dangerous`, including composite
comma-lists and boolean script grammar.

### `audit` — "prove what happened, tamper-evidently"

Append-only JSONL logger with a SHA-256 hash chain: each record hashes the previous, so any
edit, deletion, or truncation of history breaks the chain and is detectable. Log rotation
preserves numbered segments and carries the chain across the boundary.

### `target` — normalization + classification

Host normalization (IDNA/punycode for domains) and IP classification
(`ClassBlocked` / `ClassPrivate` / `ClassSafeTest` / `ClassPublic`). `IsBlocked` is the
hard-block primitive `authz` enforces first.

## Development

```
make preflight   # gofmt + vet + build + test (the CI gate)
make lint        # golangci-lint
```

Releases are automated via release-please: conventional commits on `main` open a release
PR; merging it tags `vX.Y.Z` (the Go module proxy serves it straight off the tag).

[go-wowa]: https://github.com/anatolykoptev/go-wowa
