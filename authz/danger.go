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
	return nmapFlagsDangerous(op.Flags) || nmapProfileDangerous(op.Profile)
}

// nmapFlagsDangerous reports whether any nmap CLI flag requires confirmation,
// including the --script-args unsafe=1 trigger in both split and combined forms.
func nmapFlagsDangerous(flags []string) bool {
	for i, f := range flags {
		if dangerousNmapFlags[f] {
			return true
		}
		// --script-args unsafe=1 — the trigger value follows in the next element.
		if f == "--script-args" && i+1 < len(flags) && strings.Contains(flags[i+1], "unsafe=1") {
			return true
		}
		// Combined form: "--script-args=unsafe=1" as a single element.
		if strings.HasPrefix(f, "--script-args") && strings.Contains(f, "unsafe=1") {
			return true
		}
	}
	return false
}

// nmapProfileDangerous reports whether any NSE category token requires
// confirmation. nmap --script accepts comma-lists (e.g. "exploit,dos"), so we
// tokenize and fail CLOSED if ANY token is dangerous — an exact map lookup on
// the whole string would miss composites.
func nmapProfileDangerous(profile string) bool {
	for _, tok := range splitProfileTokens(profile) {
		if dangerousNmapNSECategories[tok] {
			return true
		}
	}
	return false
}

// splitProfileTokens splits a profile string on commas and trims whitespace,
// returning the non-empty tokens. nmap --script and nuclei -tags both accept
// comma-separated lists, so danger classification must check each token. A
// single-token profile yields exactly one token, preserving prior behavior.
func splitProfileTokens(profile string) []string {
	parts := strings.Split(profile, ",")
	tokens := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

func isNucleiDangerous(op DangerOp) bool {
	// nuclei -tags accepts comma-lists (e.g. "vuln,rce"); tokenize and fail
	// CLOSED if ANY token is a dangerous tag/severity or a mutating template path.
	tokens := splitProfileTokens(op.Profile)

	// Tag / severity check.
	for _, tok := range tokens {
		if dangerousNucleiProfiles[tok] {
			return true
		}
	}

	// Template path check: fuzzing/ or cves/ + mutating method.
	for _, tok := range tokens {
		for _, prefix := range dangerousNucleiTemplatePrefixes {
			if strings.HasPrefix(tok, prefix) {
				for _, flag := range op.Flags {
					if mutatingMethods[strings.ToUpper(flag)] {
						return true
					}
				}
			}
		}
	}

	return false
}
