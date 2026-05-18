package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type tfPlanRequest struct {
	SHA string `json:"sha"`
}

// tfPlan mirrors tfApply's four-gate auth model but uses the tf-plan
// validator (different audience, sub-claim + workflow_ref-prefix pin)
// and delegates to TFPlanner. Shares applyMu with /deploy + /tf-apply
// — terraform's state lock + the shared .terraform dir would clash
// otherwise.
//
// /tf-plan never mutates infra; the serialization is purely to keep
// the workdir + state lock uncontested.
func (s *Server) tfPlan(w http.ResponseWriter, r *http.Request) {
	// Gate 1: IP allowlist.
	if !s.cfg.IPAllow.Allowed(r.RemoteAddr) {
		http.Error(w, "source IP not permitted", http.StatusForbidden)
		return
	}

	// Gate 2: Bearer token extraction.
	tok, ok := extractBearer(r.Header)
	if !ok {
		http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
		return
	}

	// Gate 3: OIDC validation against the tf-plan validator. Pinned to
	// audience=engram-tf-plan + sub=repo:<repo>:pull_request + workflow
	// path prefix. Ref varies per PR so it's not pinned.
	claims, err := s.cfg.TFPlanValidator.Validate(tok)
	if err != nil {
		http.Error(w, fmt.Sprintf("token rejected: %v", err), http.StatusUnauthorized)
		return
	}

	// Gate 4: replay protection. Shares the JTI set with /deploy and
	// /tf-apply.
	if !s.cfg.JTI.CheckAndAdd(claims.JTI) {
		http.Error(w, "token replay detected", http.StatusUnauthorized)
		return
	}

	var req tfPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
		return
	}
	if !shaPattern.MatchString(req.SHA) {
		http.Error(w, "sha must be a 40-character lowercase hex string", http.StatusBadRequest)
		return
	}

	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported by response writer", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	started := time.Now()

	events := make(chan TFPlanEvent, 8)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.cfg.TFPlanner.Plan(r.Context(), req.SHA, events)
	}()

	for ev := range events {
		_ = enc.Encode(ev)
		flusher.Flush()
	}
	runErr := <-errCh

	result := TFPlanResult{
		SHA:        req.SHA,
		StartedAt:  started,
		FinishedAt: time.Now(),
		DurationMs: time.Since(started).Milliseconds(),
	}
	if runErr != nil {
		result.Status = "fail"
		result.Error = runErr.Error()
	} else {
		result.Status = "ok"
	}

	s.mu.Lock()
	s.lastTFPlanResult = &result
	s.mu.Unlock()

	_ = enc.Encode(result)
	flusher.Flush()
}
