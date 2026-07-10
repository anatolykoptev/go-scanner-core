package target

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(false),
)

// Normalize converts a raw target string to canonical form: IPv4/IPv6
// addresses to their net.IP.String() form, hostnames to lowercase punycode
// (IDNA), and CIDRs to their masked network form. The result is a stable key
// safe to compare, dedupe, or pass into IsBlocked/Classify/Checker.CheckTarget
// without those callers re-implementing normalization. Returns an error for
// an empty string, a target carrying a URL scheme (Normalize is not a URL
// parser — strip the scheme before calling), or a string that parses as
// neither an IP, IPv6-bracketed address, CIDR, nor a valid IDNA hostname.
func Normalize(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("target must not be empty")
	}
	if strings.Contains(raw, "://") {
		return "", errors.New("target must not contain URL scheme")
	}
	if strings.Contains(raw, "/") {
		return normalizeCIDR(raw)
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return normalizeIPv6Brackets(raw)
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String(), nil
	}
	return normalizeHostname(raw)
}

// normalizeHostname converts a bare hostname to lowercase punycode and
// round-trip-verifies the result through the same IDNA profile before
// returning it. Without the round-trip check, an input like a lone invalid
// UTF-8 byte is silently mapped to U+FFFD and successfully punycode-encoded
// on the first pass, but the IDNA2008 disallowed-codepoint table rejects
// U+FFFD on decode — so a second Normalize call on that "normalized" value
// would fail, breaking the idempotency every caller relies on (log a
// normalized target, then re-check it later; compare two normalized
// values). Rejecting non-fixed-point inputs here keeps Normalize's output
// contract honest: whatever it returns, Normalize accepts unchanged.
func normalizeHostname(raw string) (string, error) {
	ascii, err := idnaProfile.ToASCII(raw)
	if err != nil {
		return "", err
	}
	// idna can encode a label like "Xn--" (case-insensitive ACE prefix, empty
	// suffix) down to "" with no error. Normalize itself treats "" as an
	// invalid target, so accepting it here would make Normalize(raw) succeed
	// while Normalize(Normalize(raw)) errors — reject it at the source instead.
	if ascii == "" {
		return "", fmt.Errorf("target: %q normalizes to an empty hostname", raw)
	}
	if again, err := idnaProfile.ToASCII(ascii); err != nil || again != ascii {
		return "", fmt.Errorf("target: %q does not normalize to a stable form", raw)
	}
	return ascii, nil
}

func normalizeCIDR(raw string) (string, error) {
	ip, network, err := net.ParseCIDR(raw)
	if err != nil {
		return "", err
	}
	if ip.Equal(network.IP) {
		return network.String(), nil
	}
	ones, _ := network.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), ones), nil
}

func normalizeIPv6Brackets(raw string) (string, error) {
	inner := raw[1 : len(raw)-1]
	if ip := net.ParseIP(inner); ip != nil {
		return ip.String(), nil
	}
	return "", errors.New("invalid bracketed address: " + raw)
}
