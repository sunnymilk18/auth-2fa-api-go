package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP resolves the caller's IP — shared by RateLimiter and Blacklist so
// both agree on who a request is "from".
//
// Only consults X-Forwarded-For when trustProxyHeaders is set — i.e. a
// reverse proxy we control sits in front and overwrites (rather than
// appends to) that header, so callers can't forge it to dodge either
// mechanism. Takes the first (client-facing) hop, since ELB/nginx/etc.
// append the real client IP at the front and any hop after that is ours.
func ClientIP(r *http.Request, trustProxyHeaders bool) string {
	if trustProxyHeaders {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if ip := strings.TrimSpace(strings.Split(fwd, ",")[0]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
