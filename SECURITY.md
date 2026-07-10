# Security Policy

go-scanner-core is a security-boundary library — SSRF hard-blocking, scope
authorization, and tamper-evident audit logging for services that reach out
to an externally-supplied target. A vulnerability here can propagate into
every consumer, so please report privately rather than opening a public
issue.

## Supported versions

Pre-1.0 (current `0.x` line): only the latest released version is supported.
There is no LTS branch yet — apply security fixes by upgrading.

## Reporting a vulnerability

Preferred: open a [GitHub private security advisory](https://github.com/anatolykoptev/go-scanner-core/security/advisories/new)
for this repository. This reaches the maintainer without disclosing the
report publicly.

Alternative: email **anatoly@koptev.me** with `[go-scanner-core security]` in
the subject. Please include:

- the affected version (module `go.sum` line or tag);
- a minimal reproduction (an allowlist YAML + target, a `DangerOp`, or a
  sequence of `Logger` calls);
- the impact you believe it has — e.g. "target X is reachable despite Y",
  "confirm_dangerous is not required for Z", "the audit chain accepts a
  tampered record without detection".

You will get an acknowledgment within **5 business days** and, for a
confirmed report, a fix or mitigation timeline within **14 days**. Please
allow a coordinated disclosure window (default 90 days, negotiable for
actively-exploited issues) before any public write-up.

## Scope

**In scope** — anything that breaks one of this library's stated invariants:

- a target that `authz.Checker.CheckTarget`/`CheckTargetDecision` allows
  despite matching `target.IsBlocked` (loopback, link-local, cloud-metadata,
  unspecified) with `allow_internal` unset;
- a `DangerOp` that `authz.IsDangerous` classifies as safe but that nmap/nuclei
  would actually treat as a dangerous/intrusive/mutating operation (a
  fail-open gap in the comma-list/boolean-grammar tokenizer);
- two distinct `audit.AuditEvent` sequences that produce the same
  `self_hash` chain (a hash-chain forgeability or collision issue), or a
  tampered/reordered/truncated record that a straightforward chain
  re-derivation (see `ExampleLogger`) fails to detect;
- a panic, unbounded resource consumption, or memory-safety issue reachable
  from `authz.ParseAllowlist`, `target.Normalize`, or any other function that
  accepts externally-supplied input (the fuzz targets in `authz/fuzz_test.go`
  and `target/fuzz_test.go` exist precisely to catch this class — a fuzzer
  input that survives longer than the seed corpus is itself a useful report).

**Out of scope** — behavior that is documented and intentional:

- `allow_internal: true` permitting a hard-blocked target that also matches
  an explicit allow rule — that is the documented, audited escape hatch, not
  a bypass;
- a wide-open `allow_cidrs: ["0.0.0.0/0"]` or similarly permissive operator
  config allowing whatever it says it allows;
- DNS-rebind style gaps where a hostname authorized at check time later
  resolves to a different (blocked) address — this library does not resolve
  DNS and says so in the `target` package doc; re-validate the resolved IP at
  your dial site (tracked upstream at go-pentest#25);
- denial of service against a consumer that calls this library with
  attacker-controlled `maxSizeBytes`, file paths, or CIDR-list sizes it
  never validates itself — validate those before they reach this library.

## Credit

Reporters who request it will be credited in the release notes for the fix,
once it ships.
