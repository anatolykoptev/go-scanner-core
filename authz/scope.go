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
	allowRanger  cidranger.Ranger
	denyRanger   cidranger.Ranger
	allowDomains []string
	denyDomains  []string
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
		allowRanger:  allowR,
		denyRanger:   denyR,
		allowDomains: allowDomains,
		denyDomains:  denyDomains,
	}, nil
}

// CheckTarget returns true if target is allowed, false if denied or not in scope.
// target must already be normalized (IP, CIDR, or domain — no http:// prefix).
func (c *Checker) CheckTarget(target string) bool {
	// Hard-block first: loopback, link-local, cloud-metadata (169.254.169.254),
	// and the unspecified address are always denied with no override. This guard
	// can only NARROW authorization (never widen it), so evaluating it before the
	// operator's allow/deny rules is safe — and it is what stops a broad or typo'd
	// allow_cidrs (e.g. 0.0.0.0/0) from turning into an SSRF primitive.
	// target.IsBlocked handles bare IPs and IP:port; for domains it returns false,
	// leaving hostname evaluation to the allow/deny matching below.
	if targetclass.IsBlocked(target) {
		return false
	}

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
