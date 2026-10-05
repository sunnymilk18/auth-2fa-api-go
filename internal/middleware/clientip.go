package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// trustedProxyPrefixes is the parsed form of TRUSTED_PROXY_CIDRS, set once
// at startup by ValidateTrustedProxyCIDRs. Empty (the default) means trust
// nothing — ClientIP behaves exactly as it did before this existed.
var trustedProxyPrefixes []netip.Prefix

// ValidateTrustedProxyCIDRs parses a comma-separated CIDR list (e.g. from
// TRUSTED_PROXY_CIDRS — "10.0.1.0/24", this API's own internal Docker
// network, where a system like empresa-backend proxies real end-user
// requests through and sets X-Forwarded-For itself).
//
// Called once at startup, before the server accepts any request. Has two
// effects: it configures the RemoteAddr-origin check ClientIP does below
// (see its own doc comment for why that check matters on its own, even
// though the request's X-Forwarded-For is resolved separately by chi's own
// ClientIPFromXFF middleware), and it returns the valid entries for
// router.go's NewRouter to register that middleware with.
//
// Returns any entries that failed to parse separately — the caller decides
// whether that's fatal; valid entries are applied regardless. An
// empty/all-invalid input clears the trusted set (equivalent to never
// calling this at all).
func ValidateTrustedProxyCIDRs(cidrs string) (valid []string, invalid []string) {
	var prefixes []netip.Prefix
	for _, raw := range strings.Split(cidrs, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			invalid = append(invalid, raw)
			continue
		}
		valid = append(valid, raw)
		prefixes = append(prefixes, p)
	}
	trustedProxyPrefixes = prefixes
	return valid, invalid
}

func isTrustedProxyAddr(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range trustedProxyPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP resolves the caller's IP — shared by RateLimiter and Blacklist so
// both agree on who a request is "from".
//
// Two checks have to both pass before X-Forwarded-For is ever trusted:
//  1. The TCP connection itself (RemoteAddr) has to originate from a
//     network listed in TRUSTED_PROXY_CIDRS.
//  2. Given that, the actual client is whatever chi's ClientIPFromXFF
//     middleware resolved for this request (see router.go — registered
//     with those same networks, walking X-Forwarded-For right-to-left and
//     skipping any hop inside them, so a multi-proxy chain or a client
//     trying to plant extra values to the left can't fool it).
//
// Check 1 matters on its own, separately from chi's middleware, even though
// it might look redundant with how ClientIPFromXFF is only ever registered
// with the same trusted networks: chi's walk never actually looks at
// RemoteAddr — it just reads whatever X-Forwarded-For says, on the
// assumption documented upstream that only a trusted proxy can reach this
// server's port at all (enforced at the firewall, not in code). This
// project has already had that exact assumption quietly fail once (ports
// meant to be internal-only stayed open to the public internet for weeks
// after a debugging session — see the project's own ops history) — so
// ClientIP re-checks RemoteAddr itself as a second, independent line of
// defense: even if something unexpected ever reaches this port directly
// again, a forged header from it still can't be trusted unless it's also
// genuinely connecting from one of these networks.
//
// With nothing configured in TRUSTED_PROXY_CIDRS (the default), both checks
// are moot — chi's middleware isn't even registered in that case (see
// router.go) — and this behaves exactly like a plain RemoteAddr read.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isTrustedProxyAddr(host) {
		if ip := chimw.GetClientIP(r.Context()); ip != "" {
			return ip
		}
	}
	return host
}
