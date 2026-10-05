package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// resolveClientIP sets the package's trusted-proxy state (same as
// ValidateTrustedProxyCIDRs does at real startup), runs a request through
// chi's ClientIPFromXFF (only when cidrs is non-empty — matching how
// router.go conditionally registers it) and returns what middleware.ClientIP
// resolves afterwards, exactly as a real handler further down the chain
// would see it. Resets the shared package state after the test so it can't
// leak into unrelated ones.
func resolveClientIP(t *testing.T, cidrs []string, remoteAddr, xForwardedFor string) string {
	t.Helper()
	ValidateTrustedProxyCIDRs(strings.Join(cidrs, ","))
	t.Cleanup(func() { ValidateTrustedProxyCIDRs("") })

	var got string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
	})

	var wrapped http.Handler = handler
	if len(cidrs) > 0 {
		wrapped = chimw.ClientIPFromXFF(cidrs...)(handler)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xForwardedFor != "" {
		r.Header.Set("X-Forwarded-For", xForwardedFor)
	}
	wrapped.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

func TestClientIP_NoTrustedProxies_IgnoresForwardedFor(t *testing.T) {
	got := resolveClientIP(t, nil, "203.0.113.5:12345", "198.51.100.9")
	if got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q (header must be ignored with nothing configured)", got, "203.0.113.5")
	}
}

func TestClientIP_TrustedProxy_UsesForwardedFor(t *testing.T) {
	got := resolveClientIP(t, []string{"10.0.1.0/24"}, "10.0.1.249:54321", "152.172.68.141")
	if got != "152.172.68.141" {
		t.Fatalf("ClientIP() = %q, want %q (RemoteAddr is inside the trusted CIDR)", got, "152.172.68.141")
	}
}

// RemoteAddr itself isn't a trusted proxy — even though the header carries
// a value, it must never be consulted. This is the check that chi's own
// ClientIPFromXFF doesn't do on its own (see ClientIP's doc comment).
func TestClientIP_UntrustedRemoteAddr_IgnoresForwardedFor(t *testing.T) {
	got := resolveClientIP(t, []string{"10.0.1.0/24"}, "198.51.100.9:12345", "1.2.3.4")
	if got != "198.51.100.9" {
		t.Fatalf("ClientIP() = %q, want %q (RemoteAddr isn't a trusted proxy, so the header must be ignored even though chi parsed it)", got, "198.51.100.9")
	}
}

// Two hops: a forged value on the left, the real client's IP on the right,
// next to the trusted proxy's own connection. Only the rightmost
// non-trusted entry may be used — never anything a client could have
// written further left in the chain.
func TestClientIP_TrustedProxy_MultipleHops_UsesRightmostUntrusted(t *testing.T) {
	got := resolveClientIP(t, []string{"10.0.1.0/24"}, "10.0.1.7:1", "9.9.9.9, 152.172.68.141")
	if got != "152.172.68.141" {
		t.Fatalf("ClientIP() = %q, want the rightmost non-trusted entry %q, not the forged leftmost one", got, "152.172.68.141")
	}
}

func TestClientIP_TrustedProxy_MissingForwardedFor_FallsBackToRemoteAddr(t *testing.T) {
	got := resolveClientIP(t, []string{"10.0.1.0/24"}, "10.0.1.249:1", "")
	if got != "10.0.1.249" {
		t.Fatalf("ClientIP() = %q, want %q (nothing to trust, fall back to RemoteAddr)", got, "10.0.1.249")
	}
}

// chi's ClientIPFromXFF fails closed on an unparseable entry — no client IP
// is set for the request at all, so ClientIP must fall back to RemoteAddr
// rather than trusting anything to the left of the garbage value.
func TestClientIP_TrustedProxy_InvalidForwardedForEntry_FallsBackToRemoteAddr(t *testing.T) {
	got := resolveClientIP(t, []string{"10.0.1.0/24"}, "10.0.1.249:1", "not-an-ip")
	if got != "10.0.1.249" {
		t.Fatalf("ClientIP() = %q, want %q (an invalid header entry must be ignored, not trusted)", got, "10.0.1.249")
	}
}

func TestClientIP_NoPortInRemoteAddr_FallsBackToRawValue(t *testing.T) {
	got := resolveClientIP(t, nil, "203.0.113.5", "") // no :port — SplitHostPort fails
	if got != "203.0.113.5" {
		t.Fatalf("ClientIP() = %q, want %q", got, "203.0.113.5")
	}
}

func TestValidateTrustedProxyCIDRs_ReportsInvalidEntries(t *testing.T) {
	t.Cleanup(func() { ValidateTrustedProxyCIDRs("") })

	valid, invalid := ValidateTrustedProxyCIDRs("10.0.1.0/24, not-a-cidr, 172.16.0.0/16")
	if len(invalid) != 1 || invalid[0] != "not-a-cidr" {
		t.Fatalf("invalid = %v, want exactly [\"not-a-cidr\"]", invalid)
	}
	if len(valid) != 2 || valid[0] != "10.0.1.0/24" || valid[1] != "172.16.0.0/16" {
		t.Fatalf("valid = %v, want [\"10.0.1.0/24\" \"172.16.0.0/16\"]", valid)
	}
}

func TestValidateTrustedProxyCIDRs_Empty(t *testing.T) {
	t.Cleanup(func() { ValidateTrustedProxyCIDRs("") })

	valid, invalid := ValidateTrustedProxyCIDRs("")
	if len(valid) != 0 || len(invalid) != 0 {
		t.Fatalf("valid=%v invalid=%v, want both empty", valid, invalid)
	}
}
