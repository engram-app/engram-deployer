package server

import (
	"context"
	"time"
)

// TFApplyEvent is a single progress message streamed back to the caller
// while a /tf-apply run executes. Phases are git_fetch | tf_init |
// tf_apply | done. Message is free-form, typically a forwarded line of
// terraform stdout.
type TFApplyEvent struct {
	Phase   string    `json:"phase"`
	Message string    `json:"message,omitempty"`
	Time    time.Time `json:"time"`
}

// TFApplyResult is the terminal record of a /tf-apply attempt. Streamed
// as the final line of the response body so callers can tail-grep for
// success.
type TFApplyResult struct {
	Status     string    `json:"status"` // "ok" | "fail"
	Error      string    `json:"error,omitempty"`
	SHA        string    `json:"sha"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMs int64     `json:"duration_ms"`
}

// TFApplier executes a terraform apply of engram-infra@sha against the
// daemon's local Docker socket. The server depends only on this interface
// so tests can substitute a fake.
//
// Run MUST close events when finished. The returned error becomes the
// "fail" reason in the terminal TFApplyResult.
type TFApplier interface {
	Run(ctx context.Context, sha string, events chan<- TFApplyEvent) error
}
