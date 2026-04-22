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
