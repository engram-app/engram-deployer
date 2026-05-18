package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// validSHA is a syntactically valid 40-char hex git SHA used by the
// happy-path tests. Real value doesn't matter — the orchestrator is
// faked.
const validSHA = "0123456789abcdef0123456789abcdef01234567"

// /tf-apply is gated behind both TFApplyValidator and TFApplier being
// configured. When omitted (the default for newTestServer), the route
// is unwired and returns 404.
func TestTFApply_DisabledWhenNotConfigured(t *testing.T) {
	s := newTestServer(t) // no withTFApplier

	req := httptest.NewRequest("POST", "/tf-apply", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+mintValidTFApplyToken(t, "jti-disabled"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route unwired)", w.Code)
	}
}

// Missing Authorization header is 401.
func TestTFApply_RejectsMissingAuth(t *testing.T) {
	s := newTestServer(t, withTFApplier(&fakeTFApplier{}))

	req := httptest.NewRequest("POST", "/tf-apply", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// A token minted for /deploy (audience=engram-deploy) MUST NOT be
// accepted by /tf-apply, even if the JTI is fresh. The validator's
// audience pin enforces the separation.
func TestTFApply_RejectsDeployAudienceToken(t *testing.T) {
	s := newTestServer(t, withTFApplier(&fakeTFApplier{}))

	req := httptest.NewRequest("POST", "/tf-apply", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	// Mint a /deploy token (wrong audience for /tf-apply).
	req.Header.Set("Authorization", "Bearer "+mintValidToken(t, "jti-wrong-aud"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (wrong audience must be refused)", w.Code)
	}
}

// IP not in the allowlist is 403 before any auth.
func TestTFApply_RejectsNonAllowlistedIP(t *testing.T) {
	s := newTestServer(t, withTFApplier(&fakeTFApplier{}))

	req := httptest.NewRequest("POST", "/tf-apply", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("Authorization", "Bearer "+mintValidTFApplyToken(t, "jti-ip-test"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// Body SHA must match the full-40-hex pattern. Anything shorter,
// uppercased, or carrying extra characters is 400. Several attack
// patterns covered (newline, shell metas, branch names).
func TestTFApply_RejectsBadSHA(t *testing.T) {
	s := newTestServer(t, withTFApplier(&fakeTFApplier{}))

	cases := []string{
		`{"sha":""}`,
		`{"sha":"abc"}`,
		`{"sha":"main"}`,
		`{"sha":"0123456789ABCDEF0123456789abcdef01234567"}`,  // upper hex
		`{"sha":"0123456789abcdef0123456789abcdef0123456"}`,   // 39 chars
		`{"sha":"0123456789abcdef0123456789abcdef012345678"}`, // 41 chars
		`{"sha":"0123456789abcdef0123456789abcdef01234567\n"}`,
		`{"sha":"0123456789abcdef0123456789abcdef01234567; rm -rf /"}`,
		`{}`,
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/tf-apply", strings.NewReader(c))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Authorization", "Bearer "+mintValidTFApplyToken(t, "jti-bad-"+c))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s got %d, want 400", c, w.Code)
		}
	}
}

// Valid token + allowed IP + healthy applier:
//   - scripted events stream as NDJSON
//   - terminal line is TFApplyResult{status:"ok", sha:<sent>}
//   - /tf-apply/status returns the same result
//   - replay of the same jti is refused
func TestTFApply_HappyPath(t *testing.T) {
	fake := &fakeTFApplier{
		scriptEvts: []TFApplyEvent{
			{Phase: "git_fetch", Message: "fetching " + validSHA, Time: time.Now()},
			{Phase: "tf_init", Message: "Initializing the backend...", Time: time.Now()},
			{Phase: "tf_apply", Message: "Apply complete! Resources: 1 added, 0 changed, 0 destroyed.", Time: time.Now()},
		},
	}
	s := newTestServer(t, withTFApplier(fake))

	body := strings.NewReader(`{"sha":"` + validSHA + `"}`)
	req := httptest.NewRequest("POST", "/tf-apply", body)
	req.RemoteAddr = "127.0.0.1:12345"
	tokenHeader := "Bearer " + mintValidTFApplyToken(t, "jti-happy-tf")
	req.Header.Set("Authorization", tokenHeader)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", got)
	}

	scanner := bufio.NewScanner(strings.NewReader(w.Body.String()))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	wantEventLines := len(fake.scriptEvts)
	if len(lines) != wantEventLines+1 {
		t.Fatalf("got %d response lines, want %d events + 1 result. body=%s",
			len(lines), wantEventLines, w.Body.String())
	}

	for i, line := range lines[:wantEventLines] {
		var ev TFApplyEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d not valid TFApplyEvent: %v (line=%s)", i, err, line)
		}
		if ev.Phase != fake.scriptEvts[i].Phase {
			t.Errorf("line %d phase = %q, want %q", i, ev.Phase, fake.scriptEvts[i].Phase)
		}
	}

	var result TFApplyResult
	if err := json.Unmarshal([]byte(lines[wantEventLines]), &result); err != nil {
		t.Fatalf("terminal line not valid TFApplyResult: %v (line=%s)", err, lines[wantEventLines])
	}
	if result.Status != "ok" {
		t.Errorf("result.Status = %q, want %q (error=%q)", result.Status, "ok", result.Error)
	}
	if result.SHA != validSHA {
		t.Errorf("result.SHA = %q, want %q", result.SHA, validSHA)
	}
	if got := fake.CalledWith(); got != validSHA {
		t.Errorf("applier called with %q, want %q", got, validSHA)
	}

	// /tf-apply/status returns the same result.
	statusReq := httptest.NewRequest("GET", "/tf-apply/status", nil)
	statusW := httptest.NewRecorder()
	s.Handler().ServeHTTP(statusW, statusReq)
	if statusW.Code != 200 {
		t.Fatalf("/tf-apply/status = %d, want 200", statusW.Code)
	}
	var statusResult TFApplyResult
	if err := json.Unmarshal(statusW.Body.Bytes(), &statusResult); err != nil {
		t.Fatalf("/tf-apply/status body not TFApplyResult: %v", err)
	}
	if statusResult.SHA != validSHA || statusResult.Status != "ok" {
		t.Errorf("/tf-apply/status mismatch: %+v", statusResult)
	}

	// Replay the same jti — must be refused.
	body2 := strings.NewReader(`{"sha":"` + validSHA + `"}`)
	req2 := httptest.NewRequest("POST", "/tf-apply", body2)
	req2.RemoteAddr = "127.0.0.1:12345"
	req2.Header.Set("Authorization", tokenHeader)
	w2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", w2.Code)
	}
}

// Failing applier surfaces in the terminal TFApplyResult.
func TestTFApply_ApplierFailure(t *testing.T) {
	fake := &fakeTFApplier{
		scriptEvts: []TFApplyEvent{
			{Phase: "git_fetch", Message: "fetching " + validSHA, Time: time.Now()},
		},
		scriptErr: errString("terraform: Error acquiring state lock"),
	}
	s := newTestServer(t, withTFApplier(fake))

	body := strings.NewReader(`{"sha":"` + validSHA + `"}`)
	req := httptest.NewRequest("POST", "/tf-apply", body)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+mintValidTFApplyToken(t, "jti-failpath-tf"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (failures are body-side)", w.Code)
	}

	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	var result TFApplyResult
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &result); err != nil {
		t.Fatalf("terminal line not TFApplyResult: %v", err)
	}
	if result.Status != "fail" {
		t.Errorf("result.Status = %q, want %q", result.Status, "fail")
	}
	if !strings.Contains(result.Error, "Error acquiring state lock") {
		t.Errorf("result.Error = %q, want substring 'Error acquiring state lock'", result.Error)
	}
}

// /tf-apply/status returns 204 before any apply has run.
func TestTFApplyStatus_204WhenEmpty(t *testing.T) {
	s := newTestServer(t, withTFApplier(&fakeTFApplier{}))

	req := httptest.NewRequest("GET", "/tf-apply/status", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}
