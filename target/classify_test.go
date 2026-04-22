package target

import "testing"

func TestClassify_RFC1918Private(t *testing.T) {
	cases := []string{"10.0.1.1", "172.16.5.5", "192.168.0.1"}
	for _, ip := range cases {
		got := Classify(ip)
		if got != ClassPrivate {
			t.Errorf("Classify(%q) = %v, want ClassPrivate", ip, got)
		}
	}
}

func TestClassify_IPv6ULAPrivate(t *testing.T) {
	got := Classify("fd00::1")
	if got != ClassPrivate {
		t.Errorf("Classify(fd00::1) = %v, want ClassPrivate", got)
	}
}

func TestClassify_ScanmeIsSafe(t *testing.T) {
	cases := []string{
		"scanme.nmap.org",
		"scanme.sh",
		"testphp.vulnweb.com",
		"zero.webappsecurity.com",
		"demo.testfire.net",
		"juice-shop.herokuapp.com",
		"dvwa.local",
	}
	for _, d := range cases {
		got := Classify(d)
		if got != ClassSafeTest {
			t.Errorf("Classify(%q) = %v, want ClassSafeTest", d, got)
		}
	}
}

func TestClassify_RFC5737SafeTest(t *testing.T) {
	cases := []string{"192.0.2.1", "198.51.100.5", "203.0.113.100"}
	for _, ip := range cases {
		got := Classify(ip)
		if got != ClassSafeTest {
			t.Errorf("Classify(%q) = %v, want ClassSafeTest", ip, got)
		}
	}
}

func TestClassify_LocalhostBlocked(t *testing.T) {
	cases := []string{"127.0.0.1", "127.255.255.255"}
	for _, ip := range cases {
		got := Classify(ip)
		if got != ClassBlocked {
			t.Errorf("Classify(%q) = %v, want ClassBlocked", ip, got)
		}
	}
}

func TestClassify_IPv6LoopbackBlocked(t *testing.T) {
	got := Classify("::1")
	if got != ClassBlocked {
		t.Errorf("Classify(::1) = %v, want ClassBlocked", got)
	}
}

func TestClassify_LinkLocalBlocked(t *testing.T) {
	got := Classify("169.254.1.1")
	if got != ClassBlocked {
		t.Errorf("Classify(169.254.1.1) = %v, want ClassBlocked", got)
	}
}

func TestClassify_PublicIP(t *testing.T) {
	cases := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	for _, ip := range cases {
		got := Classify(ip)
		if got != ClassPublic {
			t.Errorf("Classify(%q) = %v, want ClassPublic", ip, got)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	if !IsBlocked("127.0.0.1") {
		t.Error("127.0.0.1 should be blocked")
	}
	if !IsBlocked("::1") {
		t.Error("::1 should be blocked")
	}
	if IsBlocked("8.8.8.8") {
		t.Error("8.8.8.8 should not be blocked")
	}
}

func TestIsSafeTestTarget(t *testing.T) {
	if !IsSafeTestTarget("scanme.nmap.org") {
		t.Error("scanme.nmap.org should be safe test")
	}
	if !IsSafeTestTarget("192.0.2.1") {
		t.Error("192.0.2.1 should be safe test (RFC5737)")
	}
	if IsSafeTestTarget("8.8.8.8") {
		t.Error("8.8.8.8 should not be safe test")
	}
}
