package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// shaPattern enforces full 40-character git SHA. Anchored to refuse any
// extra characters (newline injection, shell metacharacters, etc) since
// the SHA is passed to git as a checkout target.
var shaPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

type tfApplyRequest struct {
	SHA string `json:"sha"`
}

// tfApply mirrors the /deploy handler's four-gate auth model but uses
// the tf-apply validator (different audience + workflow_ref pin) and
// delegates to TFApplier instead of Deployer. Concurrency with /deploy
// is serialized via s.applyMu — both endpoints mutate Docker state on
// the same host.
func (s *Server) tfApply(w http.ResponseWriter, r *http.Request) {
	// Gate 1: IP allowlist. Same allowlist as /deploy — same runner VM.
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

	// Gate 3: OIDC validation against the tf-apply validator. Pinned
	// claims here bind to engram-app/engram-infra + a tf-apply workflow
	// + audience=engram-tf-apply — distinct from /deploy's pin.
	claims, err := s.cfg.TFApplyValidator.Validate(tok)
	if err != nil {
		http.Error(w, fmt.Sprintf("token rejected: %v", err), http.StatusUnauthorized)
		return
	}

	// Gate 4: replay protection. Shares the JTI set with /deploy — a
	// token minted with the tf-apply audience cannot be replayed against
	// /deploy and vice versa, since validators enforce audience, but a
	// stolen tf-apply token cannot be reused twice here either.
	if !s.cfg.JTI.CheckAndAdd(claims.JTI) {
		http.Error(w, "token replay detected", http.StatusUnauthorized)
		return
	}

	// Parse + validate body.
	var req tfApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
		return
	}
	if !shaPattern.MatchString(req.SHA) {
		http.Error(w, "sha must be a 40-character lowercase hex string", http.StatusBadRequest)
		return
	}

	// Serialize against /deploy. Both mutate Docker state on the same
	// host; concurrent runs could leave engram-saas in an inconsistent
	// state (e.g. /deploy bumps tag while /tf-apply recreates the
	// container).
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

	events := make(chan TFApplyEvent, 8)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.cfg.TFApplier.Run(r.Context(), req.SHA, events)
	}()

	for ev := range events {
		_ = enc.Encode(ev)
		flusher.Flush()
	}
	runErr := <-errCh

	result := TFApplyResult{
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
	s.lastTFApplyResult = &result
	s.mu.Unlock()

	_ = enc.Encode(result)
	flusher.Flush()
}
