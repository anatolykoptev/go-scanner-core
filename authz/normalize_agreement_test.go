package authz

import (
	"testing"

	targetclass "github.com/anatolykoptev/go-scanner-core/target"
)

// TestNormalizeDomain_AgreesWithTargetNormalizeHostname is the point of the
// authz/target consolidation (issue #7): authz's normalizeDomain must produce
// EXACTLY what target.NormalizeHostname produces for the same input, because
// they now share one idna.Profile instead of each allocating its own. Before
// the consolidation this could silently drift (different ValidateLabels /
// StrictDomainName options), letting the same host canonicalize two
// different ways depending on which package looked at it.
func TestNormalizeDomain_AgreesWithTargetNormalizeHostname(t *testing.T) {
	hosts := []string{
		"example.com",
		"EXAMPLE.COM",
		"Example.Com",
		"münchen.de",
		"MÜNCHEN.DE",
		"xn--mnchen-3ya.de", // already punycode
		"example.com.",      // trailing dot
		"sub.example.com",
		"xn--fiqs8s", // punycode for 中国
		"a-b-c.example.com",
		// Real-world hostname authz's pre-consolidation profile rejected
		// (StrictDomainName(true) via the default MapForLookup() options) but
		// target's profile (StrictDomainName(false)) accepts — pins that
		// authz now agrees with target's more permissive character-set rule
		// rather than silently keeping its own stricter one.
		"under_score.example.com",
	}

	for _, h := range hosts {
		want, wantErr := targetclass.NormalizeHostname(h)
		got, gotErr := normalizeDomain(h)

		if (wantErr == nil) != (gotErr == nil) {
			t.Errorf("input=%q: error disagreement: target err=%v, authz err=%v", h, wantErr, gotErr)
			continue
		}
		if wantErr != nil {
			continue // both sides reject; agreement confirmed
		}
		if got != want {
			t.Errorf("input=%q: target.NormalizeHostname=%q, authz.normalizeDomain=%q (must agree)", h, want, got)
		}
	}
}

// TestCheckTarget_MatchesAcrossCaseAndIDNForm verifies the end-to-end effect
// of the shared normalizer: an allow pattern written in one case/IDN form
// matches a target presented in a different, equivalent case/IDN form.
func TestCheckTarget_MatchesAcrossCaseAndIDNForm(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowDomains: []string{"Example.COM", "münchen.de"},
	}})

	equivalents := map[string][]string{
		"Example.COM": {"example.com", "EXAMPLE.COM", "Example.com"},
		"münchen.de":  {"münchen.de", "xn--mnchen-3ya.de", "MÜNCHEN.DE"},
	}
	for pattern, targets := range equivalents {
		for _, tgt := range targets {
			if !c.CheckTarget(tgt) {
				t.Errorf("pattern %q should match target %q (case/IDN-form equivalent)", pattern, tgt)
			}
		}
	}

	if c.CheckTarget("other.com") {
		t.Error("other.com should not match either allow pattern")
	}
}

// TestNormalizeDomain_RejectsNonRoundTrippingInput pins that normalizeDomain
// itself (not just the CheckTarget end-to-end path, which can mask a
// non-error via "just didn't match any pattern") surfaces the round-trip
// idempotency guard that target.NormalizeHostname adds over authz's
// pre-consolidation profile: a lone invalid UTF-8 byte and an empty-ACE-label
// input must both error, not silently normalize to something CheckTarget
// then happens to reject for an unrelated reason (no pattern match).
func TestNormalizeDomain_RejectsNonRoundTrippingInput(t *testing.T) {
	for _, h := range []string{"\xa0", "Xn--"} {
		if _, err := normalizeDomain(h); err == nil {
			t.Errorf("normalizeDomain(%q) should error (non-round-tripping IDNA input), got nil", h)
		}
	}
}

// TestCheckTarget_FailClosedOnInvalidHost verifies a hostname the shared
// normalizer rejects is DENIED, never silently passed through unnormalized.
func TestCheckTarget_FailClosedOnInvalidHost(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowCIDRs:   []string{"0.0.0.0/0"},
		AllowDomains: []string{"*.example.com"},
	}})

	invalid := []string{
		"-.invalid", // idna: invalid label
		"\xa0",      // non-round-tripping IDNA input (see target.NormalizeHostname)
		"Xn--",      // empty-ACE-label input
	}
	for _, h := range invalid {
		if c.CheckTarget(h) {
			t.Errorf("invalid host %q must be denied (fail-closed), not silently allowed", h)
		}
	}
}

// TestNewChecker_FailClosedOnInvalidDomainPattern verifies an unparseable
// allow/deny domain pattern rejects the whole Allowlist at construction time
// rather than silently installing a no-op rule.
func TestNewChecker_FailClosedOnInvalidDomainPattern(t *testing.T) {
	_, err := NewChecker(&Allowlist{Scope: Scope{
		AllowDomains: []string{"-.invalid"},
	}})
	if err == nil {
		t.Error("expected NewChecker to error on an invalid allow_domains pattern")
	}

	_, err = NewChecker(&Allowlist{Scope: Scope{
		DenyDomains: []string{"\xa0"},
	}})
	if err == nil {
		t.Error("expected NewChecker to error on an invalid deny_domains pattern")
	}
}
