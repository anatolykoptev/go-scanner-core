package authz_test

import (
	"fmt"

	"github.com/anatolykoptev/go-scanner-core/authz"
)

// ExampleNewChecker builds a Checker from a parsed allowlist and checks a
// single in-scope domain.
func ExampleNewChecker() {
	al, err := authz.ParseAllowlist([]byte(`
scope:
  allow_domains:
    - scanme.nmap.org
`))
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}

	checker, err := authz.NewChecker(al)
	if err != nil {
		fmt.Println("checker error:", err)
		return
	}

	fmt.Println(checker.CheckTarget("scanme.nmap.org"))
	// Output: true
}

// ExampleChecker_CheckTarget shows the unconditional hard-block winning over
// a deliberately wide-open allow rule: 0.0.0.0/0 permits everything except
// the targets IsBlocked flags, which no CIDR rule can reach.
func ExampleChecker_CheckTarget() {
	al, err := authz.ParseAllowlist([]byte(`
scope:
  allow_domains:
    - scanme.nmap.org
  allow_cidrs:
    - 0.0.0.0/0
`))
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}

	checker, err := authz.NewChecker(al)
	if err != nil {
		fmt.Println("checker error:", err)
		return
	}

	// Cloud-metadata endpoint: hard-denied even though 0.0.0.0/0 is allowed.
	fmt.Println(checker.CheckTarget("169.254.169.254"))
	// In-scope domain: allowed.
	fmt.Println(checker.CheckTarget("scanme.nmap.org"))

	// Output:
	// false
	// true
}

// ExampleIsDangerous shows the fail-closed comma-list evaluation: a profile
// is dangerous if ANY token in it is, even alongside safe tokens.
func ExampleIsDangerous() {
	fmt.Println(authz.IsDangerous(authz.DangerOp{
		Tool:    authz.ToolNmap,
		Profile: "default,exploit",
	}))
	fmt.Println(authz.IsDangerous(authz.DangerOp{
		Tool:    authz.ToolNmap,
		Profile: "default,safe",
	}))
	// Output:
	// true
	// false
}
