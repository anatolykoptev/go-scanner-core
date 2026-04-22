package authz

import (
	"testing"
)

// makeChecker is a test helper that builds a Checker from raw scope fields.
func makeChecker(t *testing.T, al *Allowlist) *Checker {
	t.Helper()
	c, err := NewChecker(al)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	return c
}

func TestScope_MatchesCIDRv4(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowCIDRs: []string{"10.0.0.0/8"},
	}})

	if !c.CheckTarget("10.0.1.5") {
		t.Error("10.0.1.5 should be allowed by 10.0.0.0/8")
	}
	if c.CheckTarget("192.168.1.1") {
		t.Error("192.168.1.1 should NOT be allowed by 10.0.0.0/8")
	}
}

func TestScope_MatchesCIDRv6(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowCIDRs: []string{"2001:db8::/32"},
	}})

	if !c.CheckTarget("2001:db8::1") {
		t.Error("2001:db8::1 should be allowed by 2001:db8::/32")
	}
	if c.CheckTarget("2001:db9::1") {
		t.Error("2001:db9::1 should NOT be allowed by 2001:db8::/32")
	}
}

func TestScope_DomainWildcard(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowDomains: []string{"*.example.com"},
	}})

	if !c.CheckTarget("sub.example.com") {
		t.Error("sub.example.com should be allowed by *.example.com")
	}
	if c.CheckTarget("example.com") {
		t.Error("example.com should NOT be allowed by *.example.com (apex excluded)")
	}
	if c.CheckTarget("other.com") {
		t.Error("other.com should NOT be allowed")
	}
}

func TestScope_ExcludeWinsOverInclude(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowDomains: []string{"*.example.com"},
		DenyDomains:  []string{"prod.example.com"},
	}})

	if !c.CheckTarget("staging.example.com") {
		t.Error("staging.example.com should be allowed")
	}
	if c.CheckTarget("prod.example.com") {
		t.Error("prod.example.com should be denied (deny beats allow)")
	}
}

func TestScope_IDNNormalization(t *testing.T) {
	// "münchen.de" in Unicode normalizes to "xn--mnchen-3ya.de"
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowDomains: []string{"münchen.de"},
	}})

	// Both Unicode and punycode forms should match.
	if !c.CheckTarget("münchen.de") {
		t.Error("münchen.de (Unicode) should be allowed")
	}
	if !c.CheckTarget("xn--mnchen-3ya.de") {
		t.Error("xn--mnchen-3ya.de (punycode) should be allowed")
	}
}

func TestScope_DenyCIDR(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowCIDRs: []string{"10.0.0.0/8"},
		DenyCIDRs:  []string{"10.0.1.0/24"},
	}})

	if !c.CheckTarget("10.0.0.5") {
		t.Error("10.0.0.5 should be allowed")
	}
	if c.CheckTarget("10.0.1.5") {
		t.Error("10.0.1.5 should be denied by 10.0.1.0/24")
	}
}

func TestScope_DotPrefixDomain(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowDomains: []string{".example.com"},
	}})

	if !c.CheckTarget("sub.example.com") {
		t.Error("sub.example.com should match .example.com suffix rule")
	}
	if c.CheckTarget("example.com") {
		t.Error("example.com (apex) should NOT match .example.com suffix rule")
	}
}

func TestScope_ExactDomain(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowDomains: []string{"example.com"},
	}})

	if !c.CheckTarget("example.com") {
		t.Error("example.com should match exactly")
	}
	if c.CheckTarget("sub.example.com") {
		t.Error("sub.example.com should NOT match exact pattern example.com")
	}
}

func TestScope_InvalidCIDR_Error(t *testing.T) {
	_, err := NewChecker(&Allowlist{Scope: Scope{
		AllowCIDRs: []string{"not-a-cidr"},
	}})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestScope_InvalidDenyCIDR_Error(t *testing.T) {
	_, err := NewChecker(&Allowlist{Scope: Scope{
		DenyCIDRs: []string{"not-a-cidr"},
	}})
	if err == nil {
		t.Error("expected error for invalid deny CIDR")
	}
}
