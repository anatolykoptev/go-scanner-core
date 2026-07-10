// Package authz decides whether a caller may reach a target, and whether a
// requested scan operation needs an explicit human confirmation first.
//
// It is deny-first and fail-closed throughout:
//
//   - [Checker.CheckTarget] hard-denies loopback, link-local, and cloud-metadata
//     addresses (AWS/Azure/GCP/Oracle IMDSv4+IMDSv6, Alibaba, the unspecified
//     address) before consulting any operator-supplied allow/deny rule — no
//     allowlist entry can accidentally open one of those targets. The single
//     documented escape hatch is [Scope.AllowInternal]: even then, a
//     hard-blocked target is reachable only if it ALSO matches an explicit
//     allow rule, and [Checker.CheckTargetDecision] surfaces
//     [Decision.UsedInternalOverride] so the caller can audit-log every use.
//   - [IsDangerous] fails CLOSED: an nmap NSE category list or nuclei tag list
//     it cannot parse, or any single token in a composite comma/boolean
//     expression that is dangerous, is treated as dangerous. A scanner should
//     never silently downgrade "unsure" to "safe".
//
// authz answers only "is this target/operation in scope". It does not dial,
// resolve DNS, or classify addresses itself — that lives in the sibling
// [github.com/anatolykoptev/go-scanner-core/target] package, which authz uses
// for its hard-block check. A resolved IP can differ from the hostname
// checked here (DNS rebinding); callers that resolve after authorizing must
// re-validate at the dial site.
package authz
