package server

import (
	"context"
	"time"
)

// TFPlanEvent is a single progress message streamed back to the caller
// while a /tf-plan run executes. Phases mirror /tf-apply except the
// final shell step is `tf_plan` not `tf_apply`. Message is free-form,
// typically a forwarded line of terraform stdout.
type TFPlanEvent struct {
	Phase   string    `json:"phase"`
	Message string    `json:"message,omitempty"`
	Time    time.Time `json:"time"`
}

// TFPlanResult is the terminal record of a /tf-plan attempt. Streamed
// as the final line of the response body. /tf-plan never mutates infra
// — failure means terraform couldn't even produce a plan (init error,
// auth error, syntax error in HCL).
type TFPlanResult struct {
	Status     string    `json:"status"` // "ok" | "fail"
	Error      string    `json:"error,omitempty"`
	SHA        string    `json:"sha"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMs int64     `json:"duration_ms"`
}

// TFPlanner runs `terraform plan` for engram-infra@sha. Read-only with
// respect to live infra (state lock briefly acquired). The server
// depends only on this interface so tests can substitute a fake.
//
// Plan MUST close events when finished.
type TFPlanner interface {
	Plan(ctx context.Context, sha string, events chan<- TFPlanEvent) error
}
