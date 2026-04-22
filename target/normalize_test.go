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
