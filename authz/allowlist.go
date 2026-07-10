// Package authz provides allowlist parsing, scope matching, and danger-op enforcement.
package authz

import (
	"errors"

	"gopkg.in/yaml.v3"
)

// Scope is the parsed allowlist configuration.
type Scope struct {
	AllowDomains []string `yaml:"allow_domains"`
	AllowCIDRs   []string `yaml:"allow_cidrs"`
	AllowURLs    []string `yaml:"allow_urls"`
	DenyDomains  []string `yaml:"deny_domains"`
	DenyCIDRs    []string `yaml:"deny_cidrs"`

	// AllowInternal opts INTO scanning otherwise-hard-blocked internal targets
	// (loopback, link-local, cloud-metadata, unspecified). DEFAULT false keeps
	// the fail-closed behavior: those targets are denied with no override.
	//
	// When true, a hard-blocked target is permitted ONLY if it ALSO matches an
	// explicit allow rule (allow_cidrs / allow_domains) — it is never a blanket
	// open. This is a dangerous capability: enabling it lets a scan reach the
	// local host and cloud-metadata endpoints, so the CONSUMER MUST record every
	// permitted-internal decision in its audit log. Checker.CheckTargetDecision
	// exposes the UsedInternalOverride signal for exactly this purpose.
	AllowInternal bool `yaml:"allow_internal"`
}

// Allowlist holds the top-level allowlist YAML structure.
type Allowlist struct {
	Scope Scope `yaml:"scope"`
}

// ParseAllowlist parses YAML bytes into an Allowlist.
// Returns an error if the YAML is malformed or the scope contains no rules at all.
func ParseAllowlist(data []byte) (*Allowlist, error) {
	var al Allowlist
	if err := yaml.Unmarshal(data, &al); err != nil {
		return nil, err
	}

	s := al.Scope
	total := len(s.AllowDomains) + len(s.AllowCIDRs) + len(s.AllowURLs) +
		len(s.DenyDomains) + len(s.DenyCIDRs)
	if total == 0 {
		return nil, errors.New("authz: scope is empty — at least one rule is required")
	}

	return &al, nil
}
