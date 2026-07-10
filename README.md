# go-scanner-core

[![Go Reference](https://pkg.go.dev/badge/github.com/anatolykoptev/go-scanner-core.svg)](https://pkg.go.dev/github.com/anatolykoptev/go-scanner-core)
[![Go Report Card](https://goreportcard.com/badge/github.com/anatolykoptev/go-scanner-core)](https://goreportcard.com/report/github.com/anatolykoptev/go-scanner-core)
[![preflight](https://github.com/anatolykoptev/go-scanner-core/actions/workflows/preflight.yml/badge.svg)](https://github.com/anatolykoptev/go-scanner-core/actions/workflows/preflight.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Safety primitives for services that take an externally-supplied target and reach out
to it — security scanners, crawlers, URL fetchers. It is the **guardrail** that keeps a
powerful outbound tool from becoming a weapon: against your own infrastructure (SSRF),
against unauthorized targets (scope), and against undetectable misuse (tamper-evident audit).

No `main`, no binaries — a library you wire into the authorize/dial path of your own service.

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

It also gates dangerous scan operations — `authz.IsDangerous(authz.DangerOp{...})` fails
**closed** on nmap NSE / nuclei profiles that need explicit `confirm_dangerous`, including
composite comma-lists and boolean script grammar.

### `audit` — "prove what happened, tamper-evidently"

Append-only JSONL logger with a SHA-256 hash chain: each record hashes the previous, so any
edit, deletion, or truncation of history breaks the chain and is detectable. Log rotation
preserves numbered segments and carries the chain across the boundary.

### `target` — normalization + classification

Host normalization (IDNA/punycode for domains) and IP classification
(`ClassBlocked` / `ClassPrivate` / `ClassSafeTest` / `ClassPublic`). `IsBlocked` is the
hard-block primitive `authz` enforces first.

## Design & threat model

- **Deny-first**: a target matching a deny rule is rejected even if it also matches an
  allow rule; a target matching neither is rejected by default. There is no "default
  allow" path.
- **Fail-closed everywhere**: `authz.IsDangerous` treats an unparseable or composite
  (comma-list / boolean-grammar) profile as dangerous if *any* token in it is —
  never silently downgrades "unsure" to "safe". `authz.ParseAllowlist` rejects a scope
  with zero rules rather than defaulting to open. A malformed `allow_internal` value
  (e.g. the string `"true"` instead of the bool `true`) fails to parse instead of being
  coerced.
- **Unconditional hard-block + audited override**: `target.IsBlocked` — loopback,
  link-local (incl. cloud-metadata), the unspecified address, and the AWS IMDSv6 /
  Alibaba IMDS carve-outs — is checked *before* any operator allow/deny rule and has no
  configuration knob. The one documented escape hatch, `allow_internal: true`, still
  requires the target to ALSO match an explicit allow rule, and every use is signaled via
  `Decision.UsedInternalOverride` for the caller to audit-log.
- **Tamper-evident audit**: `audit.Logger` chains every record to the previous one by
  SHA-256, so editing, deleting, or reordering history is detectable by recomputing the
  chain (see `ExampleLogger`) — not prevented, but never silent.

**What this does NOT do**: it does not resolve DNS or re-check a target after
authorization. A hostname authorized against `Checker.CheckTarget` can later resolve to a
different (possibly blocked) address — the classic DNS-rebind gap. The caller must
re-validate the resolved IP at its actual dial site, after resolution and immediately
before connect.

## Development

```
make preflight   # gofmt + vet + build + test (the CI gate)
make lint        # golangci-lint
make cover       # race-enabled test suite + coverage percentage
```

Releases are automated via release-please: conventional commits on `main` open a release
PR; merging it tags `vX.Y.Z` (the Go module proxy serves it straight off the tag).
