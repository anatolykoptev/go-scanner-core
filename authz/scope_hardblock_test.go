package authz

import "testing"

// TestScope_HardBlockOverridesBroadAllow verifies the target-package hard-block
// is enforced inside the authz path even when a broad/typo'd allow_cidrs
// (0.0.0.0/0) would otherwise permit a loopback or cloud-metadata target.
// This is the SSRF class in finding #1: the hard-block must win over allow rules.
func TestScope_HardBlockOverridesBroadAllow(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowCIDRs: []string{"0.0.0.0/0"},
	}})

	if c.CheckTarget("127.0.0.1") {
		t.Error("127.0.0.1 must be hard-blocked regardless of allow_cidrs 0.0.0.0/0")
	}
	if c.CheckTarget("169.254.169.254") {
		t.Error("cloud-metadata 169.254.169.254 must be hard-blocked regardless of allow_cidrs 0.0.0.0/0")
	}
	// Positive control: the guard only NARROWS — a public IP stays allowed.
	if !c.CheckTarget("8.8.8.8") {
		t.Error("8.8.8.8 should remain allowed by 0.0.0.0/0 (hard-block must not widen)")
	}
}

// TestScope_AllowInternalPermitsMatchedInternal verifies the audited opt-in
// bypass: with allow_internal set AND the internal target inside an allow rule,
// the target is permitted (an authorized scan of a loopback/link-local service).
func TestScope_AllowInternalPermitsMatchedInternal(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowInternal: true,
		AllowCIDRs:    []string{"127.0.0.0/8"},
	}})

	if !c.CheckTarget("127.0.0.1") {
		t.Error("127.0.0.1 must be ALLOWED when allow_internal is set AND it matches an allow rule")
	}
	// The override signal must be observable for the consumer's audit log.
	d := c.CheckTargetDecision("127.0.0.1")
	if !d.Allowed {
		t.Error("Decision.Allowed must be true for the matched internal target")
	}
	if !d.UsedInternalOverride {
		t.Error("Decision.UsedInternalOverride must be true when an internal target is permitted via the override")
	}
}

// TestScope_AllowInternalNotBlanketBypass verifies allow_internal is NOT a
// blanket open: an internal target that matches NO allow rule is still denied.
func TestScope_AllowInternalNotBlanketBypass(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowInternal: true,
		AllowCIDRs:    []string{"10.0.0.0/8"}, // does NOT cover loopback
	}})

	if c.CheckTarget("127.0.0.1") {
		t.Error("127.0.0.1 must still be DENIED when allow_internal is set but no allow rule matches it")
	}
	if c.CheckTarget("169.254.169.254") {
		t.Error("cloud-metadata must still be DENIED when allow_internal is set but no allow rule matches it")
	}
}

// TestScope_DecisionNoOverrideForPublic verifies a normal public allow does NOT
// flag the internal-override signal.
func TestScope_DecisionNoOverrideForPublic(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowCIDRs: []string{"0.0.0.0/0"},
	}})

	d := c.CheckTargetDecision("8.8.8.8")
	if !d.Allowed {
		t.Error("8.8.8.8 should be allowed by 0.0.0.0/0")
	}
	if d.UsedInternalOverride {
		t.Error("a public target must NOT flag UsedInternalOverride")
	}
}
