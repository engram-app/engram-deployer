package server

import (
	"encoding/json"
	"net/http"
)

// /tf-plan/status returns the last TFPlanResult, or 204 if no plan
// has run. Unauthenticated — exposes only the outcome record.
func (s *Server) tfPlanStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	last := s.lastTFPlanResult
	s.mu.RUnlock()

	if last == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(last)
}
