package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// resetTrustedProxyCIDRs restores the package-level trusted-proxy state to
// "nothing trusted" after a test that configures it — trustedProxyNets is
// shared package state, so leaving it set would leak into unrelated tests.
func resetTrustedProxyCIDRs(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxyCIDRs("") })
}

func TestClientIP_NoTrustedProxies_IgnoresForwardedFor(t *testing.T) {
	resetTrustedProxyCIDRs(t)
	SetTrustedProxyCIDRs("")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")

	if got := ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q (header must be ignored with nothing configured)", got, "203.0.113.5")
	}
}

func TestClientIP_TrustedProxy_UsesForwardedFor(t *testing.T) {
	resetTrustedProxyCIDRs(t)
	SetTrustedProxyCIDRs("10.0.1.0/24")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.1.249:54321"
	r.Header.Set("X-Forwarded-For", "152.172.68.141")

	if got := ClientIP(r); got != "152.172.68.141" {
		t.Fatalf("ClientIP() = %q, want %q (RemoteAddr is inside the trusted CIDR)", got, "152.172.68.141")
	}
}

func TestClientIP_UntrustedRemoteAddr_IgnoresForwardedFor(t *testing.T) {
	resetTrustedProxyCIDRs(t)
	SetTrustedProxyCIDRs("10.0.1.0/24")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.9:12345" // outside the trusted CIDR
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := ClientIP(r); got != "198.51.100.9" {
		t.Fatalf("ClientIP() = %q, want %q (RemoteAddr isn't a trusted proxy, so the forged header must be ignored)", got, "198.51.100.9")
	}
}

func TestClientIP_TrustedProxy_MultipleForwardedFor_UsesLeftmost(t *testing.T) {
	resetTrustedProxyCIDRs(t)
	SetTrustedProxyCIDRs("10.0.1.0/24")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.1.249:1"
	r.Header.Set("X-Forwarded-For", "152.172.68.141, 10.0.1.7")

	if got := ClientIP(r); got != "152.172.68.141" {
		t.Fatalf("ClientIP() = %q, want the leftmost entry %q", got, "152.172.68.141")
	}
}

func TestClientIP_TrustedProxy_MissingForwardedFor_FallsBackToRemoteAddr(t *testing.T) {
	resetTrustedProxyCIDRs(t)
	SetTrustedProxyCIDRs("10.0.1.0/24")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.1.249:1"
	// No X-Forwarded-For set at all.

	if got := ClientIP(r); got != "10.0.1.249" {
		t.Fatalf("ClientIP() = %q, want %q (nothing to trust, fall back to RemoteAddr)", got, "10.0.1.249")
	}
}

func TestSetTrustedProxyCIDRs_ReportsInvalidEntries(t *testing.T) {
	resetTrustedProxyCIDRs(t)

	invalid := SetTrustedProxyCIDRs("10.0.1.0/24, not-a-cidr, 172.16.0.0/16")
	if len(invalid) != 1 || invalid[0] != "not-a-cidr" {
		t.Fatalf("invalid = %v, want exactly [\"not-a-cidr\"]", invalid)
	}

	// The valid entries either side of the bad one must still apply.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "172.16.5.5:1"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := ClientIP(r); got != "9.9.9.9" {
		t.Fatalf("ClientIP() = %q, want %q (valid entries around an invalid one must still be applied)", got, "9.9.9.9")
	}
}

func TestClientIP_NoPortInRemoteAddr_FallsBackToRawValue(t *testing.T) {
	resetTrustedProxyCIDRs(t)
	SetTrustedProxyCIDRs("")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5" // no :port — SplitHostPort fails

	if got := ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q", got, "203.0.113.5")
	}
}
