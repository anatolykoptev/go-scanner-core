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
