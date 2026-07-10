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
// "all" is the meta-category that runs EVERY script (including the dangerous
// ones), so it is treated as dangerous.
var dangerousNmapNSECategories = map[string]bool{
	"all":       true,
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

// profileSeparator reports whether r separates category tokens in a profile
// expression. nmap --script accepts not just comma-lists but boolean/space/paren
// grammar ("default and not intrusive", "(exploit or dos)"), so we split on
// commas, whitespace, and parentheses to surface every embedded category token.
func profileSeparator(r rune) bool {
	switch r {
	case ',', '(', ')':
		return true
	default:
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
}

// profileGrammarKeywords are nmap boolean operators — grammar, not categories —
// dropped so they are never mistaken for a category token.
var profileGrammarKeywords = map[string]bool{
	"and": true,
	"or":  true,
	"not": true,
}

// splitProfileTokens tokenizes a profile expression into its category tokens.
// nmap --script and nuclei -tags accept comma-lists AND nmap accepts boolean
// grammar, so the danger gate must fail CLOSED: any dangerous category token
// anywhere in the expression trips it. Boolean operators are dropped. A
// single-token or comma-list profile yields the same tokens as before,
// preserving prior behavior.
func splitProfileTokens(profile string) []string {
	// FieldsFunc never emits empty or separator-only fields, so only the
	// grammar-keyword filter is needed.
	fields := strings.FieldsFunc(profile, profileSeparator)
	tokens := make([]string, 0, len(fields))
	for _, f := range fields {
		if !profileGrammarKeywords[f] {
			tokens = append(tokens, f)
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
