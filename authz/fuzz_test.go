package authz

import "testing"

// blockedFuzzTargets covers each blockedPrefixes family (IPv4/IPv6 loopback
// and unspecified, IPv4 link-local incl. cloud-metadata, IPv6 link-local,
// AWS IMDSv6, Alibaba IMDS) so the invariant below exercises every hard-block
// carve-out, not just the common 169.254.169.254 case.
var blockedFuzzTargets = []string{
	"127.0.0.1",
	"::1",
	"0.0.0.0",
	"::",
	"169.254.169.254",
	"fe80::1",
	"fd00:ec2::254",
	"100.100.100.200",
}

// FuzzParseAllowlist feeds arbitrary bytes through the untrusted-input
// surface an operator's allowlist YAML represents: ParseAllowlist, then
// NewChecker on anything that parses. Two invariants must hold for ANY
// input:
//
//   - neither call panics on malformed, truncated, or adversarial YAML;
//   - when a parse succeeds AND allow_internal is not set, the resulting
//     Checker never allows a hard-blocked target — no allow_cidrs/allow_domains
//     combination the fuzzer discovers may open loopback/link-local/metadata,
//     because CheckTargetDecision consults the hard-block before any
//     operator rule.
func FuzzParseAllowlist(f *testing.F) {
	seeds := []string{
		"scope:\n  allow_domains: [\"example.com\"]\n",
		"scope:\n  allow_cidrs: [\"10.0.0.0/8\"]\n",
		"scope:\n  allow_cidrs: [\"0.0.0.0/0\"]\n",
		"scope: {}\n",
		"scope:\n  allow_internal: true\n  allow_cidrs: [\"127.0.0.0/8\"]\n",
		"scope:\n  allow_domains: [\"*.example.com\"]\n  deny_domains: [\".prod.example.com\"]\n",
		"scope:\n  allow_urls: [\"https://example.com\"]\n",
		"not valid yaml: [\n",
		"",
		"\x00\x01\x02",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		al, err := ParseAllowlist([]byte(data))
		if err != nil {
			return // malformed/empty-scope input is a valid, non-panicking outcome
		}

		checker, err := NewChecker(al)
		if err != nil {
			return // e.g. an invalid CIDR/domain pattern, or allow_urls set
		}

		if al.Scope.AllowInternal {
			// allow_internal is a documented, audited opt-in — the hard-block
			// invariant only holds for the fail-closed default.
			return
		}

		for _, target := range blockedFuzzTargets {
			if checker.CheckTarget(target) {
				t.Fatalf("hard-blocked target %q was allowed by parsed allowlist (yaml=%q)", target, data)
			}
		}
	})
}
