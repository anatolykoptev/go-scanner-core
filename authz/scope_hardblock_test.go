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

// TestScope_HardBlockIPv6LinkLocal verifies an IPv6 link-local target is denied
// even under a broad IPv6 allow entry when allow_internal is unset (finding: the
// IPv6 link-local range fe80::/10 must be hard-blocked like IPv4 link-local).
func TestScope_HardBlockIPv6LinkLocal(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowCIDRs: []string{"::/0"},
	}})

	if c.CheckTarget("fe80::1") {
		t.Error("fe80::1 must be hard-blocked regardless of allow_cidrs ::/0")
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

// TestScope_DenyFirstWinsOverInternalOverride pins that deny-first still wins
// even under allow_internal: an internal target that matches an allow rule AND a
// deny rule is DENIED — the override only lets the target reach normal
// evaluation, it never bypasses an explicit deny.
func TestScope_DenyFirstWinsOverInternalOverride(t *testing.T) {
	c := makeChecker(t, &Allowlist{Scope: Scope{
		AllowInternal: true,
		AllowCIDRs:    []string{"127.0.0.0/8"},
		DenyCIDRs:     []string{"127.0.0.1/32"},
	}})

	if c.CheckTarget("127.0.0.1") {
		t.Error("127.0.0.1 must be DENIED: deny_cidrs must win over the allow_internal override")
	}
	d := c.CheckTargetDecision("127.0.0.1")
	if d.Allowed {
		t.Error("Decision.Allowed must be false when a deny rule matches, even under allow_internal")
	}
	if d.UsedInternalOverride {
		t.Error("UsedInternalOverride must be false for a denied target (nothing was permitted via the override)")
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
