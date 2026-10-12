package ingest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gr0gu/cerberus/internal/storage"
)

// AgentAuthMiddleware validates agent authentication headers against enrolled agents.
func AgentAuthMiddleware(store *storage.Storage, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID := r.Header.Get("X-Cerberus-Agent-Id")
		if agentID == "" {
			writeError(w, http.StatusUnauthorized, "missing X-Cerberus-Agent-Id header")
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		rawToken := strings.TrimPrefix(authHeader, "Bearer ")
		if rawToken == "" {
			writeError(w, http.StatusUnauthorized, "empty bearer token")
			return
		}

		tokenHash, status, err := store.GetAgentAuth(r.Context(), agentID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid agent credentials")
			return
		}

		if status != "active" {
			writeError(w, http.StatusUnauthorized, "agent is revoked or inactive")
			return
		}

		computedHash := sha256.Sum256([]byte(rawToken))
		if subtle.ConstantTimeCompare(computedHash[:], tokenHash) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid agent credentials")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
