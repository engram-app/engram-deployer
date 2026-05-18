package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// versionPattern is the same shape ci.yml's "Extract and validate version"
// step enforces against mix.exs. Anchored to prevent shell-injection-like
// shenanigans if a future deploy impl ever shells out.
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type deployRequest struct {
	Version string `json:"version"`
	SHA     string `json:"sha,omitempty"`
}

func (s *Server) deploy(w http.ResponseWriter, r *http.Request) {
	// Gate 1: IP allowlist (cheapest, refuses unauthenticated probes early).
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

	// Gate 3: OIDC validation.
	claims, err := s.cfg.Validator.Validate(tok)
	if err != nil {
		http.Error(w, fmt.Sprintf("token rejected: %v", err), http.StatusUnauthorized)
		return
	}

	// Gate 4: replay protection. Refuse second sighting of this JTI.
	if !s.cfg.JTI.CheckAndAdd(claims.JTI) {
		http.Error(w, "token replay detected", http.StatusUnauthorized)
		return
	}

	// Parse + validate body.
	var req deployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
		return
	}
	if !versionPattern.MatchString(req.Version) {
		http.Error(w, "version must match X.Y.Z semver", http.StatusBadRequest)
		return
	}

	// Serialize against /tf-apply. Both endpoints mutate Docker state
	// on the same host; concurrent runs could leave engram-saas in an
	// inconsistent state.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	// Switch to streaming. Once we write anything, status is committed to 200;
	// success/failure conveyed via terminal {status: "ok"|"fail"} line.
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

	events := make(chan DeployEvent, 8)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.cfg.Deployer.Run(r.Context(), req.Version, events)
	}()

	for ev := range events {
		_ = enc.Encode(ev)
		flusher.Flush()
	}
	runErr := <-errCh

	result := DeployResult{
		Version:    req.Version,
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
	s.lastResult = &result
	s.mu.Unlock()

	_ = enc.Encode(result)
	flusher.Flush()
}
