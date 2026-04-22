// Package target classifies and normalizes scan targets.
package target

import "net/netip"

// Class is a target classification.
type Class int

// Classification constants ordered from most to least restricted.
const (
	ClassPublic   Class = iota // publicly routable address
	ClassPrivate               // RFC1918 / IPv6 ULA
	ClassSafeTest              // well-known test targets
	ClassBlocked               // loopback, link-local — always rejected
)

// Classify returns the Class for a normalized target string.
// normalized is either a bare IP address, an IP:port, or a hostname.
func Classify(normalized string) Class {
	if IsBlocked(normalized) {
		return ClassBlocked
	}
	if IsSafeTestTarget(normalized) {
		return ClassSafeTest
	}
	if isPrivate(normalized) {
		return ClassPrivate
	}
	return ClassPublic
}

// IsBlocked returns true for loopback and link-local addresses.
func IsBlocked(normalized string) bool {
	addr, ok := parseAddr(normalized)
	if !ok {
		return false
	}
	for _, pfx := range blockedPrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// IsSafeTestTarget returns true for well-known authorized test targets.
func IsSafeTestTarget(normalized string) bool {
	// Check domain names first.
	if safeTestDomains[normalized] {
		return true
	}
	// Check RFC5737 documentation IP ranges.
	addr, ok := parseAddr(normalized)
	if !ok {
		return false
	}
	for _, pfx := range safeTestPrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// isPrivate returns true for RFC1918 / IPv6 ULA addresses.
func isPrivate(normalized string) bool {
	addr, ok := parseAddr(normalized)
	if !ok {
		return false
	}
	for _, pfx := range privatePrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// parseAddr extracts a netip.Addr from a normalized target string.
// It handles bare IPs and strips port if present.
func parseAddr(s string) (netip.Addr, bool) {
	// Try bare IP first.
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	// Try addr:port.
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}
