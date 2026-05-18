package server

import (
	"encoding/json"
	"net/http"
)

// /tf-apply/status returns the last TFApplyResult, or 204 if no apply
// has run. Unauthenticated — same shape as /status; exposes only the
// outcome record, never tokens.
func (s *Server) tfApplyStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	last := s.lastTFApplyResult
	s.mu.RUnlock()

	if last == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(last)
}
