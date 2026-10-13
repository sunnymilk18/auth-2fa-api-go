package auth

import (
	"net"
	"net/http"
	"net/netip"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// clientIP resolves the caller's real IP for auth_events, the same
// trusted-proxy-aware logic as middleware.ClientIP (see that function's
// doc comment for the full reasoning) — duplicated locally rather than
// imported: internal/middleware already imports this package (for
// APIClientIDFromContext — see ratelimit.go), so the reverse import would
// cycle. Same reasoning, and the same kind of local reimplementation, as
// auth.PushRequestLimiter's own doc comment for why it reimplements
// middleware.RateLimiter's counter locally instead of importing it.
//
// trustedProxyPrefixes is parsed once in NewService from the same
// validated TRUSTED_PROXY_CIDRS list router.go/cmd/api/main.go already
// pass to httpserver.NewRouter — a request's RemoteAddr must itself
// originate from one of these networks before X-Forwarded-For (resolved
// by chi's own ClientIPFromXFF middleware, already registered globally in
// router.go) is ever trusted.
func clientIP(r *http.Request, trustedProxyPrefixes []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	for _, p := range trustedProxyPrefixes {
		if p.Contains(addr) {
			if real := chimw.GetClientIP(r.Context()); real != "" {
				return real
			}
			break
		}
	}
	return host
}

// parseTrustedProxyCIDRs parses the already-validated CIDR strings
// cmd/api/main.go passes to NewService — invalid entries were already
// dropped and logged by middleware.ValidateTrustedProxyCIDRs before this
// package ever sees them, so errors here are silently skipped rather than
// re-validated a second time.
func parseTrustedProxyCIDRs(cidrs []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}
