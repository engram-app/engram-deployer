package tfapply

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// initMaxAttempts is the total number of `terraform init` tries (1 initial
// + 2 retries). Kept small: retries exist to ride out a brief blip, not to
// outlast a real outage.
const initMaxAttempts = 3

// initBackoffs is the wait before retry attempt N (index 0 = before the
// 2nd try). len must be initMaxAttempts-1 — asserted in init() so bumping
// initMaxAttempts without extending this panics at startup, not mid-deploy
// on an out-of-range index.
var initBackoffs = []time.Duration{5 * time.Second, 10 * time.Second}

func init() {
	if len(initBackoffs) != initMaxAttempts-1 {
		panic(fmt.Sprintf("initBackoffs has %d entries, want initMaxAttempts-1 = %d",
			len(initBackoffs), initMaxAttempts-1))
	}
}

// retryableInitSignals are lowercased substrings that mark a `terraform
// init` failure as a transient network blip downloading providers/modules:
// TLS handshake timeouts, refused/reset connections, DNS failures, dropped
// connections, rate limits, and registry 5xx. Matching is allowlist-only —
// anything not on this list (HCL/syntax errors, auth/permission failures,
// checksum mismatches, 4xx-not-429) fails fast so a retry never masks a
// real bug.
var retryableInitSignals = []string{
	"tls handshake timeout",
	"connection refused",
	"connection reset",
	"i/o timeout",
	"no such host",                         // DNS (Go resolver)
	"temporary failure in name resolution", // DNS (glibc resolver)
	"network is unreachable",
	"unexpected eof",
	"client.timeout exceeded", // Go http.Client deadline
	"429 too many requests",
	"502 bad gateway",
	"503 service unavailable",
	"504 gateway timeout",
	"registry service is unreachable",
}

// retryableInitError reports whether the combined output of a failed
// `terraform init` matches a transient network signal. See
// retryableInitSignals for the policy and rationale.
func retryableInitError(output string) bool {
	lower := strings.ToLower(output)
	for _, sig := range retryableInitSignals {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// newCapturingEmit wraps parent with an accumulator so a failed init's
// combined output can be classified after the fact. streamCommand forwards
// stdout + stderr from two concurrent goroutines, so the accumulator is
// mutex-guarded against torn/lost writes. snapshot is safe to call once
// both streamers have stopped (and is itself locked for good measure).
func newCapturingEmit(parent emitFn) (emit emitFn, snapshot func() string) {
	var mu sync.Mutex
	var b strings.Builder
	emit = func(phase, msg string) {
		mu.Lock()
		b.WriteString(msg)
		b.WriteByte('\n')
		mu.Unlock()
		parent(phase, msg)
	}
	snapshot = func() string {
		mu.Lock()
		defer mu.Unlock()
		return b.String()
	}
	return emit, snapshot
}

// waitFn sleeps for d unless ctx is cancelled first, in which case it
// returns ctx.Err(). Injected so tests skip real backoff sleeps.
type waitFn func(ctx context.Context, d time.Duration) error

// sleepCtx is the production waitFn: a ctx-cancellable sleep.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// withInitRetry runs run up to initMaxAttempts times, retrying ONLY when
// the captured output is classified transient by retryableInitError. run
// returns (combinedOutput, err) for one attempt; a nil err means success.
//
// Every retry emits a tf_init_retry "::warning::" line through emit so a
// flake surfaces in the CI step output instead of passing silently. A
// cancelled ctx or a non-retryable error stops immediately and returns
// that error.
func withInitRetry(ctx context.Context, emit emitFn, wait waitFn, run func(attempt int) (string, error)) error {
	var lastErr error
	for attempt := 1; attempt <= initMaxAttempts; attempt++ {
		out, err := run(attempt)
		if err == nil {
			return nil
		}
		lastErr = err

		if ctx.Err() != nil || attempt == initMaxAttempts || !retryableInitError(out) {
			return err
		}

		backoff := initBackoffs[attempt-1]
		emit("tf_init_retry", fmt.Sprintf(
			"::warning:: terraform init hit a transient network error (attempt %d/%d), retrying in %s: %v",
			attempt, initMaxAttempts, backoff, err,
		))
		if werr := wait(ctx, backoff); werr != nil {
			return lastErr
		}
	}
	return lastErr
}
