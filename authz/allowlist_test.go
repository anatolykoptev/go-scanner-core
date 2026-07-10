package authz

import (
	"os"
	"testing"
)

func TestAllowlist_ParsesValidYAML(t *testing.T) {
	data, err := os.ReadFile("testdata/allowlist_valid.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	al, err := ParseAllowlist(data)
	if err != nil {
		t.Fatalf("ParseAllowlist returned error: %v", err)
	}

	if al == nil {
		t.Fatal("ParseAllowlist returned nil")
	}

	if len(al.Scope.AllowDomains) != 2 {
		t.Errorf("want 2 allow_domains, got %d", len(al.Scope.AllowDomains))
	}

	if len(al.Scope.DenyDomains) != 1 {
		t.Errorf("want 1 deny_domains, got %d", len(al.Scope.DenyDomains))
	}

	if len(al.Scope.AllowCIDRs) != 1 {
		t.Errorf("want 1 allow_cidrs, got %d", len(al.Scope.AllowCIDRs))
	}
}

func TestAllowlist_RejectsMalformed(t *testing.T) {
	data, err := os.ReadFile("testdata/allowlist_malformed.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	_, err = ParseAllowlist(data)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

func TestAllowlist_RequiresAtLeastOneRule(t *testing.T) {
	data := []byte(`scope: {}`)

	_, err := ParseAllowlist(data)
	if err == nil {
		t.Fatal("expected error for empty scope, got nil")
	}
}

// TestAllowlist_AllowInternalAloneIsEmptyScope pins that allow_internal is a
// modifier, not a rule: a scope whose only content is allow_internal: true has
// no allow/deny rules and must be rejected as empty (the flag can never open a
// target by itself).
func TestAllowlist_AllowInternalAloneIsEmptyScope(t *testing.T) {
	data := []byte("scope:\n  allow_internal: true\n")

	_, err := ParseAllowlist(data)
	if err == nil {
		t.Fatal("expected empty-scope error for allow_internal-only scope, got nil")
	}
}

// TestAllowlist_AllowInternalNonBoolFailsClosed pins that a non-bool
// allow_internal value fails to parse rather than being coerced to true — a
// mistyped flag must never silently enable the internal-override capability.
func TestAllowlist_AllowInternalNonBoolFailsClosed(t *testing.T) {
	cases := map[string]string{
		"int":           "scope:\n  allow_cidrs: [\"127.0.0.0/8\"]\n  allow_internal: 1\n",
		"quoted-string": "scope:\n  allow_cidrs: [\"127.0.0.0/8\"]\n  allow_internal: \"true\"\n",
	}
	for name, yml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAllowlist([]byte(yml)); err == nil {
				t.Errorf("expected parse error for non-bool allow_internal (%s), got nil", name)
			}
		})
	}
}
