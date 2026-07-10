package target

import "testing"

// FuzzNormalize feeds arbitrary strings through Normalize, the entry point
// for every externally-supplied target string before it reaches IsBlocked,
// Classify, or a Checker. Two invariants must hold for ANY input:
//
//   - Normalize never panics, on malformed IPs, malformed CIDRs, malformed
//     IDNA labels, or arbitrary bytes;
//   - Normalize is idempotent: re-normalizing an already-normalized value
//     returns it unchanged. A normalizer that isn't idempotent means a
//     double-normalized value (e.g. logged, then re-checked) could silently
//     drift from the value that was actually authorized.
func FuzzNormalize(f *testing.F) {
	seeds := []string{
		"127.0.0.1",
		"[::1]",
		"[2001:db8::1]",
		"example.com",
		"EXAMPLE.COM",
		"münchen.de",
		"xn--mnchen-3ya.de",
		"10.0.0.0/8",
		"10.0.0.5/8",
		"2001:db8::/32",
		"",
		"http://example.com",
		"999.999.999.999",
		"[not-an-ip]",
		"a..b",
		"-.-",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := Normalize(raw)
		if err != nil {
			return // rejecting invalid input is a valid, non-panicking outcome
		}

		got2, err2 := Normalize(got)
		if err2 != nil {
			t.Fatalf("Normalize(%q) = %q, but re-normalizing that output failed: %v", raw, got, err2)
		}
		if got2 != got {
			t.Fatalf("Normalize not idempotent: Normalize(%q) = %q, Normalize(%q) = %q", raw, got, got, got2)
		}
	})
}
