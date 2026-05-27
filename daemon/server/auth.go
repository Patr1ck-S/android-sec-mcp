package server

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func BearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if token == "" || !strings.HasPrefix(got, prefix) || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(got, prefix)), []byte(token)) != 1 {
			http.Error(w, "missing or invalid bearer token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
