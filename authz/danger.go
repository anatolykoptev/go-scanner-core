// Package authz provides allowlist validation, scope matching,
// and danger-operation classification for scan requests.
package authz

import (
	"net/http"
	"strings"
)

// ScanTool identifies the scanning tool.
type ScanTool string

// Supported scan tools for danger classification.
const (
	ToolNmap   ScanTool = "nmap"
	ToolNuclei ScanTool = "nuclei"
	ToolTLS    ScanTool = "tls"
)

// DangerOp describes a potentially dangerous scan operation.
type DangerOp struct {
	Tool    ScanTool
	Profile string   // nmap NSE category, nuclei tag/severity/template path
	Flags   []string // additional nmap flags or nuclei HTTP methods
}

// dangerousNmapFlags are nmap CLI flags that require confirmation.
var dangerousNmapFlags = map[string]bool{
	"-A":  true,
	"-O":  true,
	"-sS": true,
}

// dangerousNmapNSECategories are NSE script categories that require confirmation.
// "vuln" is intentionally absent — informational, default-allow.
var dangerousNmapNSECategories = map[string]bool{
	"exploit":   true,
	"dos":       true,
	"brute":     true,
	"intrusive": true,
	"fuzzer":    true,
	"malware":   true,
}

// dangerousNucleiProfiles are nuclei tags/severities that require confirmation.
var dangerousNucleiProfiles = map[string]bool{
	"intrusive": true,
	"dos":       true,
	"fuzz":      true,
	"rce":       true,
	"critical":  true,
}

// dangerousNucleiTemplatePrefixes are template path prefixes that require
// confirmation when paired with mutating HTTP methods.
var dangerousNucleiTemplatePrefixes = []string{"fuzzing/", "cves/"}

// mutatingMethods are HTTP methods that modify server state.
var mutatingMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodDelete: true,
}

// dangerousTLSProfiles are TLS probe types that require confirmation.
var dangerousTLSProfiles = map[string]bool{
	"renegotiation": true,
	"ccs_injection": true,
}

// IsDangerous returns true if the operation requires confirm_dangerous=true.
func IsDangerous(op DangerOp) bool {
	switch op.Tool {
	case ToolNmap:
		return isNmapDangerous(op)
	case ToolNuclei:
		return isNucleiDangerous(op)
	case ToolTLS:
		return dangerousTLSProfiles[op.Profile]
	default:
		return false
	}
}

func isNmapDangerous(op DangerOp) bool {
	// Check individual flags.
	scriptArgsUnsafe := false
	for i, f := range op.Flags {
		if dangerousNmapFlags[f] {
			return true
		}
		// --script-args unsafe=1 — the trigger value must follow in the next element.
		if f == "--script-args" {
			next := ""
			if i+1 < len(op.Flags) {
				next = op.Flags[i+1]
			}
			if strings.Contains(next, "unsafe=1") {
				scriptArgsUnsafe = true
			}
		}
		// Also handle combined form: "--script-args=unsafe=1" or "unsafe=1" as single element.
		if strings.HasPrefix(f, "--script-args") && strings.Contains(f, "unsafe=1") {
			scriptArgsUnsafe = true
		}
	}
	if scriptArgsUnsafe {
		return true
	}

	// Check NSE category profile.
	return dangerousNmapNSECategories[op.Profile]
}

func isNucleiDangerous(op DangerOp) bool {
	// Tag / severity check.
	if dangerousNucleiProfiles[op.Profile] {
		return true
	}

	// Template path check: fuzzing/ or cves/ + mutating method.
	for _, prefix := range dangerousNucleiTemplatePrefixes {
		if strings.HasPrefix(op.Profile, prefix) {
			for _, flag := range op.Flags {
				if mutatingMethods[strings.ToUpper(flag)] {
					return true
				}
			}
		}
	}

	return false
}
