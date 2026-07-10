package authz

import "testing"

// nmap --script and nuclei -tags accept comma-separated lists. The confirm-gate
// must tokenize the profile and flag the op dangerous if ANY token is dangerous —
// otherwise a composite like "exploit,dos" misses every exact map key and a
// dangerous scan runs without confirm_dangerous (finding #2, fails OPEN).

func TestDanger_NmapCompositeProfile(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "exploit,dos"}
	if !IsDangerous(op) {
		t.Error("nmap composite profile 'exploit,dos' must be dangerous (contains exploit+dos)")
	}
}

func TestDanger_NmapCompositeProfileSafeFirst(t *testing.T) {
	// A benign token first must not mask a dangerous token later.
	op := DangerOp{Tool: ToolNmap, Profile: "default,intrusive"}
	if !IsDangerous(op) {
		t.Error("nmap composite profile 'default,intrusive' must be dangerous (contains intrusive)")
	}
}

func TestDanger_NmapCompositeProfileWithSpaces(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "safe, brute"}
	if !IsDangerous(op) {
		t.Error("nmap composite profile 'safe, brute' must be dangerous (contains brute, whitespace trimmed)")
	}
}

func TestDanger_NmapCompositeAllSafe(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "default,safe,discovery"}
	if IsDangerous(op) {
		t.Error("nmap composite profile with only safe tokens must NOT be dangerous")
	}
}

func TestDanger_NucleiCompositeProfile(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "vuln,rce"}
	if !IsDangerous(op) {
		t.Error("nuclei composite tags 'vuln,rce' must be dangerous (contains rce)")
	}
}

func TestDanger_NucleiCompositeSeverity(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "low,critical"}
	if !IsDangerous(op) {
		t.Error("nuclei composite severity 'low,critical' must be dangerous (contains critical)")
	}
}
