package middleware

import (
	"net/http"
	"os"
	"strings"
)

// CORS allows browser clients from the configured frontend origins to call the API.
// Set CORS_ALLOWED_ORIGINS to a comma-separated list in deployed environments.
func CORS() func(http.Handler) http.Handler {
	allowedOrigins := configuredOrigins()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowedOrigins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			}

			if r.Method == http.MethodOptions {
				if origin != "" && allowedOrigins[origin] {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.Error(w, "CORS origin not allowed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func configuredOrigins() map[string]bool {
	value := os.Getenv("CORS_ALLOWED_ORIGINS")
	if value == "" {
		value = "http://localhost:5173,http://127.0.0.1:5173"
	}

	origins := make(map[string]bool)
	for _, origin := range strings.Split(value, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins[origin] = true
		}
	}
	return origins
}
