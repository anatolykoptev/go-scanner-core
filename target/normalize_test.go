package target

import (
	"testing"
)

func TestNormalize_IPv4(t *testing.T) {
	got, err := Normalize("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "192.168.1.1" {
		t.Errorf("want 192.168.1.1, got %q", got)
	}
}

func TestNormalize_IPv6Brackets(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
	}
	for _, tc := range tests {
		got, err := Normalize(tc.input)
		if err != nil {
			t.Errorf("input=%q: unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("input=%q: want %q, got %q", tc.input, tc.want, got)
		}
	}
}

func TestNormalize_DomainLowercase(t *testing.T) {
	got, err := Normalize("Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "example.com" {
		t.Errorf("want example.com, got %q", got)
	}
}

func TestNormalize_DomainPunycode(t *testing.T) {
	got, err := Normalize("münchen.de")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// golang.org/x/net/idna should encode ü → xn--
	if got != "xn--mnchen-3ya.de" {
		t.Errorf("want xn--mnchen-3ya.de, got %q", got)
	}
}

func TestNormalize_CIDR(t *testing.T) {
	got, err := Normalize("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "192.168.1.0/24" {
		t.Errorf("want 192.168.1.0/24, got %q", got)
	}
}

func TestNormalize_RejectsURLs(t *testing.T) {
	urls := []string{
		"http://example.com",
		"https://example.com/path",
	}
	for _, u := range urls {
		_, err := Normalize(u)
		if err == nil {
			t.Errorf("input=%q: expected error, got nil", u)
		}
	}
}

func TestNormalize_RejectsEmpty(t *testing.T) {
	_, err := Normalize("")
	if err == nil {
		t.Error("expected error for empty string, got nil")
	}
}

func TestNormalize_CIDRHostBitsSet(t *testing.T) {
	// 192.168.1.5/24 — host bits are set, should keep the original host IP.
	got, err := Normalize("192.168.1.5/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "192.168.1.5/24" {
		t.Errorf("want 192.168.1.5/24, got %q", got)
	}
}

func TestNormalize_InvalidCIDR(t *testing.T) {
	_, err := Normalize("999.999.999.999/24")
	if err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}

func TestNormalize_InvalidBrackets(t *testing.T) {
	_, err := Normalize("[notanip]")
	if err == nil {
		t.Error("expected error for invalid bracketed address, got nil")
	}
}

func TestNormalize_InvalidHostname(t *testing.T) {
	// A hostname that idna will reject (e.g. label too long or invalid chars).
	_, err := Normalize("-.invalid")
	if err == nil {
		t.Error("expected error for invalid hostname, got nil")
	}
}

// TestNormalize_RejectsNonRoundTrippingUTF8 pins a bug FuzzNormalize found:
// a lone invalid UTF-8 byte was silently mapped to U+FFFD and successfully
// punycode-encoded on the first ToASCII pass, but re-normalizing that
// "normalized" output failed — U+FFFD is disallowed by the IDNA2008 table
// consulted on decode. Normalize must reject the input outright rather than
// return a value it would itself refuse on a second call.
func TestNormalize_RejectsNonRoundTrippingUTF8(t *testing.T) {
	_, err := Normalize("\xa0")
	if err == nil {
		t.Fatal("expected error for a non-round-tripping IDNA input, got nil")
	}
}

// TestNormalize_RejectsEmptyACELabel pins a second bug FuzzNormalize found:
// "Xn--" (an ACE prefix with an empty suffix) encodes to "" with no IDNA
// error, but Normalize treats "" as an invalid target — so without this
// guard, Normalize("Xn--") would succeed while re-normalizing its own
// output failed.
func TestNormalize_RejectsEmptyACELabel(t *testing.T) {
	_, err := Normalize("Xn--")
	if err == nil {
		t.Fatal("expected error for an empty-ACE-label input, got nil")
	}
}

// TestNormalizeHostname_RejectsURLAuthorityAndControlChars pins the SSRF
// regression found in review of the authz consolidation (issue #7 follow-up):
// StrictDomainName(false) drops STD3 ASCII rules, so IDNA alone happily
// accepts a URL-authority delimiter or control byte inside what is supposed
// to be a bare hostname — e.g. "169.254.169.254#x.example.com" round-trips
// through ToASCII unchanged with no error. A downstream authz allow/deny
// suffix match (".example.com") then matches the trailing junk, while a
// caller that later feeds this string into url.Parse/net.Dial reads only
// the authority up to the delimiter — the cloud-metadata host, not the
// evaluated suffix. NormalizeHostname must reject any hostname whose ASCII
// form is not pure LDH+dot+underscore, closing that parser differential.
//
// Some payloads contain '/', which routes through Normalize's CIDR branch
// rather than the hostname arm, so those are exercised via NormalizeHostname
// directly (the entry point authz.normalizeDomain calls); the rest also go
// through the full Normalize dispatch.
func TestNormalizeHostname_RejectsURLAuthorityAndControlChars(t *testing.T) {
	payloads := []string{
		"evil.com#x.example.com",
		"corp.evil.com#x.example.com",
		"169.254.169.254#x.example.com",
		"evil.com?x.example.com",
		"evil.com/x.example.com",
		"evil.com@x.example.com",
		"evil.com:x.example.com",
		`evil.com\x.example.com`,
		"evil.com x.example.com",
		"evil.com\tx.example.com",
		"evil.com\nx.example.com",
		"evil.com%2fx.example.com",
		"evil.com[x].example.com",
	}
	for _, p := range payloads {
		if _, err := NormalizeHostname(p); err == nil {
			t.Errorf("NormalizeHostname(%q) should reject a URL-authority/control-char payload, got nil error", p)
		}
	}
	// The subset without '/' also exercises the full Normalize dispatch.
	for _, p := range []string{
		"evil.com#x.example.com",
		"corp.evil.com#x.example.com",
		"169.254.169.254#x.example.com",
		"evil.com?x.example.com",
		"evil.com@x.example.com",
		"evil.com:x.example.com",
	} {
		if _, err := Normalize(p); err == nil {
			t.Errorf("Normalize(%q) should reject a URL-authority/control-char payload, got nil error", p)
		}
	}
}

// TestNormalize_KeepsUnderscoreHostnames is the narrow-fix regression guard:
// the delimiter/control-char reject must not also reject the legitimate
// underscore-bearing hostnames (e.g. "_dmarc"-style DNS TXT record hosts)
// that motivated moving authz onto target's more permissive
// StrictDomainName(false) profile in the first place.
func TestNormalize_KeepsUnderscoreHostnames(t *testing.T) {
	got, err := Normalize("_dmarc.example.com")
	if err != nil {
		t.Fatalf("unexpected error for a legitimate underscore hostname: %v", err)
	}
	if got != "_dmarc.example.com" {
		t.Errorf("want _dmarc.example.com, got %q", got)
	}
}
