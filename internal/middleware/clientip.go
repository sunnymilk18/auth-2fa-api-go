package middleware

import (
	"net"
	"net/http"
	"strings"
)

// trustedProxyNets is the parsed form of TRUSTED_PROXY_CIDRS (see
// SetTrustedProxyCIDRs). nil — the default — means no proxy is trusted:
// ClientIP behaves exactly as it did before this existed.
var trustedProxyNets []*net.IPNet

// SetTrustedProxyCIDRs configures which networks ClientIP trusts
// X-Forwarded-For from, parsed from a comma-separated CIDR list (e.g.
// "10.0.1.0/24" — this API's own internal Docker network, where a system
// like empresa-backend proxies real end-user requests through and sets the
// header itself). Called once at startup, before the server accepts any
// request. Returns any entries that failed to parse (the caller decides
// whether that's fatal); valid entries are applied regardless. An empty
// string clears the trusted set (the default — equivalent to never calling
// this at all).
func SetTrustedProxyCIDRs(cidrs string) (invalid []string) {
	var nets []*net.IPNet
	for _, raw := range strings.Split(cidrs, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			invalid = append(invalid, raw)
			continue
		}
		nets = append(nets, n)
	}
	trustedProxyNets = nets
	return invalid
}

// ClientIP resolves the caller's IP — shared by RateLimiter and Blacklist
// so both agree on who a request is "from".
//
// Reads X-Forwarded-For only when the TCP connection itself (RemoteAddr)
// comes from a network listed in TRUSTED_PROXY_CIDRS — otherwise the header
// is ignored and RemoteAddr is used as-is, same as always. This matters
// because trusting the header unconditionally would let anyone dodge both
// the rate limits and the blacklist by just setting an arbitrary value on
// every request; restricting it to known proxy networks means only a
// system that already controls where the TCP connection originates (one we
// deployed ourselves) can supply it. With nothing configured (the
// default), this behaves exactly like before TRUSTED_PROXY_CIDRS existed.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isTrustedProxy(host) {
		if fwd := leftmostForwardedFor(r); fwd != "" {
			return fwd
		}
	}
	return host
}

func isTrustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// leftmostForwardedFor returns the first address in X-Forwarded-For — the
// original client. Safe to take at face value here specifically because
// this API only ever trusts a direct, single hop (a system like
// empresa-backend setting the header itself from its own already-verified
// client IP, not relaying/appending to an existing chain) — there's no
// multi-hop chain to worry about skipping trusted entries in from the
// right, the way a public-facing edge proxy would need to.
func leftmostForwardedFor(r *http.Request) string {
	v := r.Header.Get("X-Forwarded-For")
	if v == "" {
		return ""
	}
	first, _, _ := strings.Cut(v, ",")
	return strings.TrimSpace(first)
}
