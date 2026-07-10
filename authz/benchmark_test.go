package authz

import "testing"

// buildBenchChecker builds a Checker over an allowlist sized like a real
// deployment: a handful of exact/wildcard domain patterns, several CIDR
// blocks (including one IPv6), and a couple of deny rules — enough that the
// benchmark exercises the radix-tree CIDR lookup and the linear domain-list
// walk at a realistic scale rather than a single-entry toy list.
func buildBenchChecker(b *testing.B) *Checker {
	b.Helper()
	al := &Allowlist{Scope: Scope{
		AllowDomains: []string{
			"scanme.nmap.org", "scanme.sh", "*.example.com", "*.internal.example.com",
			"api.example.com", "*.staging.example.net", "test.example.org", "*.qa.example.io",
		},
		AllowCIDRs: []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
		},
		DenyDomains: []string{"blocked.example.com", "*.quarantine.example.com"},
		DenyCIDRs:   []string{"10.0.99.0/24"},
	}}
	checker, err := NewChecker(al)
	if err != nil {
		b.Fatalf("NewChecker: %v", err)
	}
	return checker
}

// BenchmarkCheckTarget covers the authz hot path across every branch
// CheckTargetDecision takes: the unconditional hard-block short-circuit, a
// CIDR-trie allow hit, a CIDR-trie deny hit, an exact/wildcard domain hit,
// and a full miss that walks every deny then every allow pattern.
func BenchmarkCheckTarget(b *testing.B) {
	checker := buildBenchChecker(b)

	cases := []struct {
		name   string
		target string
	}{
		{"AllowDomainExact", "scanme.nmap.org"},
		{"AllowDomainWildcard", "svc.internal.example.com"},
		{"AllowCIDRv4", "10.0.1.5"},
		{"AllowCIDRv6", "2001:db8::1"},
		{"DenyCIDR", "10.0.99.5"},
		{"HardBlocked", "169.254.169.254"},
		{"NoMatch", "unknown.example.org"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				checker.CheckTarget(tc.target)
			}
		})
	}
}
