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

// /tf-plan is gated behind both TFPlanValidator and TFPlanner being
// configured. Without them, the route returns 404.
func TestTFPlan_DisabledWhenNotConfigured(t *testing.T) {
	s := newTestServer(t) // no withTFPlanner

	req := httptest.NewRequest("POST", "/tf-plan", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+mintValidTFPlanToken(t, "jti-plan-disabled"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route unwired)", w.Code)
	}
}

// A token minted for /tf-apply (audience=engram-tf-apply) MUST NOT be
// accepted by /tf-plan, even with a fresh JTI. Audience pin enforces.
func TestTFPlan_RejectsTFApplyAudienceToken(t *testing.T) {
	s := newTestServer(t, withTFPlanner(&fakeTFPlanner{}))

	req := httptest.NewRequest("POST", "/tf-plan", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+mintValidTFApplyToken(t, "jti-plan-wrong-aud"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (wrong audience must be refused)", w.Code)
	}
}

// IP not in allowlist is 403 before any auth.
func TestTFPlan_RejectsNonAllowlistedIP(t *testing.T) {
	s := newTestServer(t, withTFPlanner(&fakeTFPlanner{}))

	req := httptest.NewRequest("POST", "/tf-plan", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("Authorization", "Bearer "+mintValidTFPlanToken(t, "jti-plan-ip"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// SHA format guard mirrors /tf-apply.
func TestTFPlan_RejectsBadSHA(t *testing.T) {
	s := newTestServer(t, withTFPlanner(&fakeTFPlanner{}))

	bad := []string{
		`{"sha":""}`,
		`{"sha":"abc"}`,
		`{"sha":"0123456789ABCDEF0123456789abcdef01234567"}`,
		`{"sha":"0123456789abcdef0123456789abcdef01234567; rm -rf /"}`,
		`{}`,
	}
	for _, c := range bad {
		req := httptest.NewRequest("POST", "/tf-plan", strings.NewReader(c))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Authorization", "Bearer "+mintValidTFPlanToken(t, "jti-plan-bad-"+c))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s got %d, want 400", c, w.Code)
		}
	}
}

// Happy path: scripted events stream as NDJSON, terminal TFPlanResult
// has status=ok, /tf-plan/status returns the same record, replay 401.
func TestTFPlan_HappyPath(t *testing.T) {
	fake := &fakeTFPlanner{
		scriptEvts: []TFPlanEvent{
			{Phase: "git_fetch", Message: "fetching " + validSHA, Time: time.Now()},
			{Phase: "tf_init", Message: "Initializing the backend...", Time: time.Now()},
			{Phase: "tf_plan", Message: "Plan: 1 to add, 0 to change, 0 to destroy.", Time: time.Now()},
		},
	}
	s := newTestServer(t, withTFPlanner(fake))

	req := httptest.NewRequest("POST", "/tf-plan", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	tokenHeader := "Bearer " + mintValidTFPlanToken(t, "jti-plan-happy")
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
	wantLines := len(fake.scriptEvts) + 1
	if len(lines) != wantLines {
		t.Fatalf("got %d lines, want %d. body=%s", len(lines), wantLines, w.Body.String())
	}

	var result TFPlanResult
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &result); err != nil {
		t.Fatalf("terminal line not TFPlanResult: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("result.Status = %q, want ok (error=%q)", result.Status, result.Error)
	}
	if result.SHA != validSHA {
		t.Errorf("result.SHA = %q, want %q", result.SHA, validSHA)
	}
	if got := fake.CalledWith(); got != validSHA {
		t.Errorf("planner called with %q, want %q", got, validSHA)
	}

	// /tf-plan/status returns same record.
	statusReq := httptest.NewRequest("GET", "/tf-plan/status", nil)
	statusW := httptest.NewRecorder()
	s.Handler().ServeHTTP(statusW, statusReq)
	if statusW.Code != 200 {
		t.Fatalf("/tf-plan/status = %d, want 200", statusW.Code)
	}

	// Replay refused.
	req2 := httptest.NewRequest("POST", "/tf-plan", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req2.RemoteAddr = "127.0.0.1:12345"
	req2.Header.Set("Authorization", tokenHeader)
	w2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", w2.Code)
	}
}

// Failing planner surfaces in terminal TFPlanResult.
func TestTFPlan_PlannerFailure(t *testing.T) {
	fake := &fakeTFPlanner{
		scriptEvts: []TFPlanEvent{
			{Phase: "git_fetch", Message: "fetching", Time: time.Now()},
		},
		scriptErr: errString("terraform: provider not found"),
	}
	s := newTestServer(t, withTFPlanner(fake))

	req := httptest.NewRequest("POST", "/tf-plan", strings.NewReader(`{"sha":"`+validSHA+`"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+mintValidTFPlanToken(t, "jti-plan-fail"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (failures are body-side)", w.Code)
	}
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	var result TFPlanResult
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &result); err != nil {
		t.Fatalf("terminal line not TFPlanResult: %v", err)
	}
	if result.Status != "fail" {
		t.Errorf("result.Status = %q, want fail", result.Status)
	}
	if !strings.Contains(result.Error, "provider not found") {
		t.Errorf("result.Error = %q, want substring 'provider not found'", result.Error)
	}
}

func TestTFPlanStatus_204WhenEmpty(t *testing.T) {
	s := newTestServer(t, withTFPlanner(&fakeTFPlanner{}))

	req := httptest.NewRequest("GET", "/tf-plan/status", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}
