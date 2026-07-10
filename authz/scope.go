package authz

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/yl2chen/cidranger"
	"golang.org/x/net/idna"

	targetclass "github.com/anatolykoptev/go-scanner-core/target"
)

// Checker evaluates targets against an Allowlist using deny-first logic.
type Checker struct {
	allowRanger   cidranger.Ranger
	denyRanger    cidranger.Ranger
	allowDomains  []string
	denyDomains   []string
	allowInternal bool
}

// Decision is the outcome of evaluating a target. It carries the plain Allowed
// verdict plus UsedInternalOverride, which is true when a hard-blocked internal
// target (loopback / link-local / cloud-metadata / unspecified) was permitted
// only because allow_internal is set. The consumer MUST audit-log any decision
// where UsedInternalOverride is true — that is the whole point of the flag being
// explicit and observable rather than a silent bypass.
type Decision struct {
	Allowed              bool
	UsedInternalOverride bool
}

// NewChecker creates a Checker from an Allowlist.
func NewChecker(al *Allowlist) (*Checker, error) {
	if len(al.Scope.AllowURLs) > 0 {
		return nil, errors.New("AllowURLs is not yet implemented; remove allow_urls from allowlist")
	}

	allowR := cidranger.NewPCTrieRanger()
	denyR := cidranger.NewPCTrieRanger()

	for _, cidr := range al.Scope.AllowCIDRs {
		network, err := parseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("allow_cidrs: %w", err)
		}
		if err := allowR.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
			return nil, fmt.Errorf("allow_cidrs insert: %w", err)
		}
	}

	for _, cidr := range al.Scope.DenyCIDRs {
		network, err := parseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("deny_cidrs: %w", err)
		}
		if err := denyR.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
			return nil, fmt.Errorf("deny_cidrs insert: %w", err)
		}
	}

	allowDomains, err := normalizeDomains(al.Scope.AllowDomains)
	if err != nil {
		return nil, fmt.Errorf("allow_domains: %w", err)
	}

	denyDomains, err := normalizeDomains(al.Scope.DenyDomains)
	if err != nil {
		return nil, fmt.Errorf("deny_domains: %w", err)
	}

	return &Checker{
		allowRanger:   allowR,
		denyRanger:    denyR,
		allowDomains:  allowDomains,
		denyDomains:   denyDomains,
		allowInternal: al.Scope.AllowInternal,
	}, nil
}

// CheckTarget returns true if target is allowed, false if denied or not in scope.
// target must already be normalized (IP, CIDR, or domain — no http:// prefix).
//
// Use CheckTargetDecision when you need the audit signal for internal-override
// permits; CheckTarget is the plain-bool shim over it.
func (c *Checker) CheckTarget(target string) bool {
	return c.CheckTargetDecision(target).Allowed
}

// CheckTargetDecision evaluates target and reports both the verdict and whether
// the allow_internal override was exercised (UsedInternalOverride).
//
// Hard-blocked targets (loopback, link-local, cloud-metadata 169.254.169.254,
// the unspecified address) are DENIED with no override UNLESS allow_internal is
// set — in which case the target falls through to the NORMAL allow/deny
// evaluation and is permitted ONLY if it also matches an explicit allow rule.
// So an internal target is reachable only when BOTH allow_internal is set AND it
// matches an allow rule; the flag is never a blanket open. Callers MUST audit
// any decision where UsedInternalOverride is true.
func (c *Checker) CheckTargetDecision(target string) Decision {
	// target.IsBlocked handles bare IPs and IP:port; for domains it returns
	// false, leaving hostname evaluation to the allow/deny matching below.
	blocked := targetclass.IsBlocked(target)
	if blocked && !c.allowInternal {
		return Decision{Allowed: false}
	}

	allowed := c.evaluate(target)
	return Decision{
		Allowed:              allowed,
		UsedInternalOverride: blocked && allowed,
	}
}

// evaluate applies the operator's deny-first allow/deny rules to a normalized
// target, without the internal hard-block. It is the shared core behind
// CheckTargetDecision.
func (c *Checker) evaluate(target string) bool {
	if ip, err := netip.ParseAddr(target); err == nil {
		return c.checkIP(ip)
	}

	normalized, err := normalizeDomain(target)
	if err != nil {
		return false
	}
	return c.checkDomain(normalized)
}

// checkIP applies deny-first logic for IP addresses.
func (c *Checker) checkIP(ip netip.Addr) bool {
	netIP := net.IP(ip.Unmap().AsSlice())

	denied, err := c.denyRanger.ContainingNetworks(netIP)
	if err == nil && len(denied) > 0 {
		return false
	}

	allowed, err := c.allowRanger.ContainingNetworks(netIP)
	return err == nil && len(allowed) > 0
}

// checkDomain applies deny-first logic for domain names (already punycode-normalized).
func (c *Checker) checkDomain(domain string) bool {
	for _, pattern := range c.denyDomains {
		if domainMatches(pattern, domain) {
			return false
		}
	}
	for _, pattern := range c.allowDomains {
		if domainMatches(pattern, domain) {
			return true
		}
	}
	return false
}

// domainMatches checks whether domain matches a pattern.
//   - "example.com"   → exact match only
//   - ".example.com"  → any subdomain (not the apex)
//   - "*.example.com" → any direct subdomain (same as .example.com semantics)
func domainMatches(pattern, domain string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(domain, suffix)
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(domain, pattern)
	}
	return pattern == domain
}

// normalizeDomains converts a slice of domain patterns to punycode.
func normalizeDomains(domains []string) ([]string, error) {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		n, err := normalizeDomainPattern(d)
		if err != nil {
			return nil, fmt.Errorf("invalid domain %q: %w", d, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// normalizeDomainPattern normalizes a pattern, preserving any leading . or *. prefix.
func normalizeDomainPattern(pattern string) (string, error) {
	prefix := ""
	bare := pattern
	switch {
	case strings.HasPrefix(pattern, "*."):
		prefix = "*."
		bare = pattern[2:]
	case strings.HasPrefix(pattern, "."):
		prefix = "."
		bare = pattern[1:]
	}

	n, err := normalizeDomain(bare)
	if err != nil {
		return "", err
	}
	return prefix + n, nil
}

// normalizeDomain converts a bare domain to lowercase punycode via IDNA.
func normalizeDomain(domain string) (string, error) {
	p := idna.New(idna.MapForLookup(), idna.Transitional(false))
	return p.ToASCII(domain)
}

// parseCIDR parses a CIDR string and returns a *net.IPNet for cidranger.
func parseCIDR(cidr string) (*net.IPNet, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if addr.Is6() && prefix.Addr().Is4In6() {
		// adjust bits for unmapped prefix
		bits -= 96
	}
	ip := net.IP(addr.AsSlice())
	const bitsPerByte = 8
	mask := net.CIDRMask(bits, len(ip)*bitsPerByte)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}
