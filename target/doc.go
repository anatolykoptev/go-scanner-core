// Package target normalizes and classifies scan targets — the primitive
// [github.com/anatolykoptev/go-scanner-core/authz] builds its unconditional
// SSRF hard-block on top of.
//
// Two independent jobs live here:
//
//   - [Normalize] canonicalizes a raw target string (IPv4, IPv6 with or
//     without brackets, a hostname via IDNA/punycode, or a CIDR) so that later
//     comparisons — allowlist matching, classification, dedup — operate on one
//     consistent form instead of every caller inventing its own.
//   - [Classify] and [IsBlocked] answer "how sensitive is this normalized
//     target". [IsBlocked] is the hard-block primitive: it is unconditional and
//     carries no configuration knob, by design — the one thing this library
//     will not let an operator's YAML accidentally widen. It flags loopback,
//     link-local (including cloud-metadata endpoints reachable over
//     link-local, e.g. 169.254.169.254), the unspecified address, and IPv6
//     equivalents (AWS IMDSv6's fd00:ec2::254, Alibaba's IMDS IPv4).
//
// [Classify] additionally distinguishes RFC1918/ULA private space
// ([ClassPrivate], allowlist-overridable) from well-known authorized test
// targets ([ClassSafeTest]) from everything else ([ClassPublic]).
//
// target does not resolve hostnames — a domain that later resolves to a
// blocked address is not caught by IsBlocked at authorization time. Re-check
// the resolved IP at the dial site (DNS rebinding).
package target
