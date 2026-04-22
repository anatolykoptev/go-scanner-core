package authz

import "testing"

func TestDanger_FlagsSYNScan(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Flags: []string{"-sS"}}
	if !IsDangerous(op) {
		t.Error("nmap -sS should be dangerous")
	}
}

func TestDanger_FlagsNSEVulnCategory(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "vuln"}
	if IsDangerous(op) {
		t.Error("nmap NSE vuln category should NOT be dangerous")
	}
}

func TestDanger_PassesSafeProfile(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "top1000"}
	if IsDangerous(op) {
		t.Error("nmap top1000 profile with no dangerous flags should be safe")
	}
}

func TestDanger_NmapAggressiveFlag(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Flags: []string{"-A"}}
	if !IsDangerous(op) {
		t.Error("nmap -A should be dangerous")
	}
}

func TestDanger_NmapOSFlag(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Flags: []string{"-O"}}
	if !IsDangerous(op) {
		t.Error("nmap -O should be dangerous")
	}
}

func TestDanger_NmapScriptArgsUnsafe(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Flags: []string{"--script-args", "unsafe=1"}}
	if !IsDangerous(op) {
		t.Error("nmap --script-args unsafe=1 should be dangerous")
	}
}

func TestDanger_NmapNSEExploitCategory(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "exploit"}
	if !IsDangerous(op) {
		t.Error("nmap NSE exploit category should be dangerous")
	}
}

func TestDanger_NmapNSEDosCategory(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "dos"}
	if !IsDangerous(op) {
		t.Error("nmap NSE dos category should be dangerous")
	}
}

func TestDanger_NmapNSEBruteCategory(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "brute"}
	if !IsDangerous(op) {
		t.Error("nmap NSE brute category should be dangerous")
	}
}

func TestDanger_NmapNSEIntrusiveCategory(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "intrusive"}
	if !IsDangerous(op) {
		t.Error("nmap NSE intrusive category should be dangerous")
	}
}

func TestDanger_NmapNSEFuzzerCategory(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "fuzzer"}
	if !IsDangerous(op) {
		t.Error("nmap NSE fuzzer category should be dangerous")
	}
}

func TestDanger_NmapNSEMalwareCategory(t *testing.T) {
	op := DangerOp{Tool: ToolNmap, Profile: "malware"}
	if !IsDangerous(op) {
		t.Error("nmap NSE malware category should be dangerous")
	}
}

func TestDanger_NucleiCriticalSeverity(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "critical"}
	if !IsDangerous(op) {
		t.Error("nuclei critical severity should be dangerous")
	}
}

func TestDanger_NucleiIntrusiveTag(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "intrusive"}
	if !IsDangerous(op) {
		t.Error("nuclei intrusive tag should be dangerous")
	}
}

func TestDanger_NucleiDosTag(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "dos"}
	if !IsDangerous(op) {
		t.Error("nuclei dos tag should be dangerous")
	}
}

func TestDanger_NucleiRceTag(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "rce"}
	if !IsDangerous(op) {
		t.Error("nuclei rce tag should be dangerous")
	}
}

func TestDanger_NucleiFuzzTag(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "fuzz"}
	if !IsDangerous(op) {
		t.Error("nuclei fuzz tag should be dangerous")
	}
}

func TestDanger_NucleiSafeProfile(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "info"}
	if IsDangerous(op) {
		t.Error("nuclei info severity should be safe")
	}
}

func TestDanger_NucleiTemplateFuzzingPath(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "fuzzing/sqli.yaml", Flags: []string{"POST"}}
	if !IsDangerous(op) {
		t.Error("nuclei fuzzing/ template with POST should be dangerous")
	}
}

func TestDanger_NucleiTemplateCvesPathPOST(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "cves/2024-1234.yaml", Flags: []string{"POST"}}
	if !IsDangerous(op) {
		t.Error("nuclei cves/ template with POST should be dangerous")
	}
}

func TestDanger_NucleiTemplateCvesPathGET(t *testing.T) {
	op := DangerOp{Tool: ToolNuclei, Profile: "cves/2024-1234.yaml", Flags: []string{"GET"}}
	if IsDangerous(op) {
		t.Error("nuclei cves/ template with GET only should be safe")
	}
}

func TestDanger_TLSRenegotiation(t *testing.T) {
	op := DangerOp{Tool: ToolTLS, Profile: "renegotiation"}
	if !IsDangerous(op) {
		t.Error("TLS renegotiation probe should be dangerous")
	}
}

func TestDanger_TLSCCSInjection(t *testing.T) {
	op := DangerOp{Tool: ToolTLS, Profile: "ccs_injection"}
	if !IsDangerous(op) {
		t.Error("TLS CCS injection should be dangerous")
	}
}

func TestDanger_TLSSafeProfile(t *testing.T) {
	op := DangerOp{Tool: ToolTLS, Profile: "cert_check"}
	if IsDangerous(op) {
		t.Error("TLS cert_check should be safe")
	}
}

func TestDanger_UnknownTool(t *testing.T) {
	op := DangerOp{Tool: "unknown", Profile: "anything"}
	if IsDangerous(op) {
		t.Error("unknown tool with arbitrary profile should be safe")
	}
}
