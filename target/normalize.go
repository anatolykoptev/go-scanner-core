package target

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(false),
)

// hostnameCharset is the belt-and-suspenders gate NormalizeHostname applies
// after IDNA: LDH (letters/digits/hyphen) + dot + underscore only, anchored
// full-string. StrictDomainName(false) above is deliberately permissive (it
// is what lets a legitimate underscore host like "_dmarc.example.com"
// through), but that permissiveness is IDNA's STD3-ASCII-rule check, not a
// URL-authority-aware check: it also accepts delimiter/control bytes
// ('/','@',':','#','?','%','[',']','\\', space, tab, newline, ...) inside
// what is supposed to be a bare hostname. A caller that suffix-matches such
// a string against an allow/deny domain list (see authz.domainMatches) can
// be tricked into a false allow — the string
// "169.254.169.254#x.example.com" suffix-matches "*.example.com" — while a
// downstream url.Parse/net.Dial on the "normalized" value only reads the
// authority up to the delimiter, i.e. the cloud-metadata host, not the
// evaluated suffix. Rejecting anything outside this charset closes that
// parser differential without giving up underscore support (switching to
// StrictDomainName(true) instead would reject underscores too). The first/
// last character classes include '_' too — real underscore-prefixed labels
// like "_dmarc.example.com" (DKIM/SPF TXT records) and "_acme-challenge."
// start with it.
var hostnameCharset = regexp.MustCompile(`^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$`)

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
	return NormalizeHostname(raw)
}

// NormalizeHostname converts a bare hostname to lowercase punycode and
// round-trip-verifies the result through the same IDNA profile before
// returning it. Without the round-trip check, an input like a lone invalid
// UTF-8 byte is silently mapped to U+FFFD and successfully punycode-encoded
// on the first pass, but the IDNA2008 disallowed-codepoint table rejects
// U+FFFD on decode — so a second Normalize call on that "normalized" value
// would fail, breaking the idempotency every caller relies on (log a
// normalized target, then re-check it later; compare two normalized
// values). Rejecting non-fixed-point inputs here keeps Normalize's output
// contract honest: whatever it returns, Normalize accepts unchanged.
//
// NormalizeHostname is the single IDNA entry point for this module: any
// package that needs to canonicalize a bare hostname (not the full
// IP/CIDR/hostname dispatch Normalize does) should call this directly rather
// than allocating its own idna.Profile — a second hand-rolled profile with
// different options can silently diverge from this one and canonicalize the
// same host two different ways.
func NormalizeHostname(raw string) (string, error) {
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
	// StrictDomainName(false) permits non-STD3 ASCII (needed for underscore
	// hosts) but also permits URL-authority delimiters and control bytes —
	// see hostnameCharset's doc comment. Reject those explicitly; IDNA alone
	// is not a sufficient hostname validator here.
	if !hostnameCharset.MatchString(ascii) {
		return "", fmt.Errorf("target: %q contains a character outside the hostname charset (letters, digits, hyphen, dot, underscore)", raw)
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
