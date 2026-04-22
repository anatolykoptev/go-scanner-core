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
