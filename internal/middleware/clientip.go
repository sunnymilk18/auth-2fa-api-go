package middleware

import (
	"net"
	"net/http"
)

// ClientIP resolves the caller's IP from the real TCP connection — shared
// by RateLimiter and Blacklist so both agree on who a request is "from".
//
// Deliberately never consults X-Forwarded-For: trusting it safely requires
// knowing the request actually came through a proxy we control (so the
// header couldn't have been forged by the caller itself), which this API
// has no way to verify today — there's no allowlist of trusted proxy
// IPs, just the request itself. A wrong "yes, trust it" here would let
// anyone dodge both the rate limits and the blacklist by setting an
// arbitrary value on every request. If this API ever does need to sit
// behind a proxy that hides the real client IP, the fix is a real
// trusted-proxies allowlist (checking RemoteAddr is one of them before
// reading the header) — not a blanket trust-it-or-not flag.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
