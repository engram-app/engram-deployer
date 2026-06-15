package tfapply

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// streamCommand forwards a command's stdout + stderr from two concurrent
// goroutines into the same emit closure. The capturing sink tfInit uses to
// classify init failures must therefore tolerate concurrent emits without
// racing or losing lines. Run under -race; an unsynchronized accumulator
// fails here even though the single-goroutine init tests stay green.
func TestNewCapturingEmit_ConcurrentEmitsSafe(t *testing.T) {
	capEmit, snapshot := newCapturingEmit(func(string, string) {})

	const goroutines, perGoroutine = 2, 500
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				capEmit("tf_init", "line")
			}
		}()
	}
	wg.Wait()

	got := strings.Count(snapshot(), "line")
	if want := goroutines * perGoroutine; got != want {
		t.Errorf("captured %d lines, want %d (lost writes => race)", got, want)
	}
}

// The capturing sink forwards every line to the parent emit (so streamed
// output still reaches the CI event channel) in addition to accumulating
// it for classification.
func TestNewCapturingEmit_ForwardsToParent(t *testing.T) {
	var forwarded []string
	capEmit, snapshot := newCapturingEmit(func(_, msg string) {
		forwarded = append(forwarded, msg)
	})

	capEmit("tf_init", "TLS handshake timeout")

	if len(forwarded) != 1 || forwarded[0] != "TLS handshake timeout" {
		t.Errorf("parent received %v, want [TLS handshake timeout]", forwarded)
	}
	if !strings.Contains(snapshot(), "TLS handshake timeout") {
		t.Errorf("snapshot = %q, want it to contain the line", snapshot())
	}
}

// retryableInitError is the line between "transient network blip, safe to
// retry" and "real bug, retrying just hides it". The allowlist must match
// the former and reject the latter — never blanket-retry.
func TestRetryableInitError(t *testing.T) {
	retryable := []struct {
		name   string
		output string
	}{
		{"tls handshake timeout", `Error while installing carlpett/sops v1.4.1: github.com: Get "https://...": net/http: TLS handshake timeout`},
		{"connection refused", "dial tcp 140.82.112.3:443: connect: connection refused"},
		{"connection reset", "read tcp 10.0.0.1:50000->140.82.112.3:443: read: connection reset by peer"},
		{"i/o timeout", `Get "https://registry.terraform.io/...": dial tcp: i/o timeout`},
		{"dns no such host", `Get "https://github.com/...": dial tcp: lookup github.com: no such host`},
		{"dns temporary failure", "lookup registry.terraform.io: Temporary failure in name resolution"},
		{"network unreachable", "dial tcp 140.82.112.3:443: connect: network is unreachable"},
		{"unexpected eof", "error downloading provider: unexpected EOF"},
		{"client timeout exceeded", `Client.Timeout exceeded while awaiting headers`},
		{"429 too many requests", "registry returned 429 Too Many Requests"},
		{"502 bad gateway", "the registry responded with 502 Bad Gateway"},
		{"503 service unavailable", "Error: 503 Service Unavailable"},
		{"504 gateway timeout", "received 504 Gateway Timeout from registry"},
		{"registry unreachable", "the registry service is unreachable, please try again later"},
	}
	for _, c := range retryable {
		t.Run("retryable/"+c.name, func(t *testing.T) {
			if !retryableInitError(c.output) {
				t.Errorf("retryableInitError(%q) = false, want true", c.output)
			}
		})
	}

	notRetryable := []struct {
		name   string
		output string
	}{
		{"empty", ""},
		{"hcl syntax", "Error: Unsupported argument\n\n  on main.tf line 12, in resource ..."},
		{"invalid block", "Error: Invalid block definition\n\n  on providers.tf line 3"},
		{"401 unauthorized", "Error: failed to query available provider packages: 401 Unauthorized"},
		{"403 forbidden", "Error: 403 Forbidden when accessing the module registry"},
		{"auth failed", "fatal: Authentication failed for 'https://github.com/...'"},
		{"permission denied", "Error: open /mnt/state: permission denied"},
		{"checksum mismatch", "Error: registry.terraform.io/carlpett/sops: checksum list has unexpected SHA-256 hash"},
		{"404 not found", "Error: provider registry registry.terraform.io does not have a provider named ...: 404 Not Found"},
	}
	for _, c := range notRetryable {
		t.Run("not-retryable/"+c.name, func(t *testing.T) {
			if retryableInitError(c.output) {
				t.Errorf("retryableInitError(%q) = true, want false", c.output)
			}
		})
	}
}

// noWait is a wait func that returns immediately so tests don't sleep the
// real 5s/10s backoff.
func noWait(context.Context, time.Duration) error { return nil }

// A transient failure on the first attempt followed by success returns nil
// and surfaces exactly one tf_init_retry warning so the flake is visible
// (never accept a silent rerun-pass).
func TestWithInitRetry_RetriesTransientThenSucceeds(t *testing.T) {
	var calls int
	var emitted []string
	emit := func(phase, msg string) {
		if phase == "tf_init_retry" {
			emitted = append(emitted, msg)
		}
	}
	run := func(attempt int) (string, error) {
		calls++
		if attempt == 1 {
			return "net/http: TLS handshake timeout", errors.New("exit status 1")
		}
		return "", nil
	}

	if err := withInitRetry(context.Background(), emit, noWait, run); err != nil {
		t.Fatalf("withInitRetry returned %v, want nil", err)
	}
	if calls != 2 {
		t.Errorf("run called %d times, want 2", calls)
	}
	if len(emitted) != 1 {
		t.Fatalf("emitted %d tf_init_retry warnings, want 1: %v", len(emitted), emitted)
	}
	if !strings.Contains(emitted[0], "::warning::") {
		t.Errorf("retry warning = %q, want it to contain ::warning::", emitted[0])
	}
}

// A non-retryable (real) error fails fast: run is called exactly once and
// no retry warning is emitted. This is the guard against masking real bugs.
func TestWithInitRetry_FailsFastOnRealError(t *testing.T) {
	var calls int
	var retries int
	emit := func(phase, msg string) {
		if phase == "tf_init_retry" {
			retries++
		}
	}
	wantErr := errors.New("exit status 1")
	run := func(attempt int) (string, error) {
		calls++
		return "Error: Unsupported argument on main.tf line 12", wantErr
	}

	err := withInitRetry(context.Background(), emit, noWait, run)
	if !errors.Is(err, wantErr) {
		t.Fatalf("withInitRetry returned %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("run called %d times on non-retryable error, want 1", calls)
	}
	if retries != 0 {
		t.Errorf("emitted %d retry warnings on non-retryable error, want 0", retries)
	}
}

// A persistently transient failure exhausts all attempts (3) and returns
// the last error rather than looping forever.
func TestWithInitRetry_ExhaustsAttempts(t *testing.T) {
	var calls int
	run := func(attempt int) (string, error) {
		calls++
		return "connection refused", errors.New("exit status 1")
	}

	err := withInitRetry(context.Background(), func(string, string) {}, noWait, run)
	if err == nil {
		t.Fatal("withInitRetry returned nil after exhausting attempts, want error")
	}
	if calls != 3 {
		t.Errorf("run called %d times, want 3 (max attempts)", calls)
	}
}

// A cancelled context stops retrying even when the error is transient — the
// daemon is shutting down, so don't keep spinning.
func TestWithInitRetry_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls int
	run := func(attempt int) (string, error) {
		calls++
		return "connection refused", errors.New("exit status 1")
	}

	err := withInitRetry(ctx, func(string, string) {}, noWait, run)
	if err == nil {
		t.Fatal("withInitRetry returned nil with cancelled ctx, want error")
	}
	if calls != 1 {
		t.Errorf("run called %d times with cancelled ctx, want 1", calls)
	}
}
