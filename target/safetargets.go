package target

import "net/netip"

// blockedPrefixes are always denied with no override.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),        // IPv4 loopback
	netip.MustParsePrefix("::1/128"),            // IPv6 loopback
	netip.MustParsePrefix("0.0.0.0/32"),         // IPv4 unspecified
	netip.MustParsePrefix("::/128"),             // IPv6 unspecified
	netip.MustParsePrefix("169.254.0.0/16"),     // IPv4 link-local (incl. cloud-metadata 169.254.169.254)
	netip.MustParsePrefix("fe80::/10"),          // IPv6 link-local
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDSv6 endpoint (hard-block over the fd00::/8 ULA range)
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud IMDS endpoint (100.64.0.0/10 CGN space)
}

// privatePrefixes are RFC1918 and IPv6 ULA — denied unless allowlisted.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fd00::/8"), // IPv6 ULA
}

// safeTestPrefixes are RFC5737 documentation ranges — always allowed for unit tests.
var safeTestPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

// safeTestDomains are well-known authorized test targets.
var safeTestDomains = map[string]bool{
	"scanme.nmap.org":          true,
	"scanme.sh":                true,
	"testphp.vulnweb.com":      true,
	"zero.webappsecurity.com":  true,
	"demo.testfire.net":        true,
	"juice-shop.herokuapp.com": true,
	"dvwa.local":               true,
}
