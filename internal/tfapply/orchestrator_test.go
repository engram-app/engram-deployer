package tfapply

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/engram-app/engram-deployer/internal/server"
)

// validate() catches missing required fields before any subprocess
// runs. Cheap smoke test that protects against misconfigured Server
// wiring.
func TestOrchestrator_ValidateMissingFields(t *testing.T) {
	cases := []struct {
		name string
		orch Orchestrator
		want string
	}{
		{"missing RepoURL", Orchestrator{RootDir: "a", WorkDir: "/tmp/w"}, "RepoURL"},
		{"missing RootDir", Orchestrator{RepoURL: "https://x", WorkDir: "/tmp/w"}, "RootDir"},
		{"missing WorkDir", Orchestrator{RepoURL: "https://x", RootDir: "a"}, "WorkDir"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.orch.validate()
			if err == nil {
				t.Fatal("validate() returned nil, want error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("validate() error = %q, want substring %q", err.Error(), c.want)
			}
		})
	}
}

// Run() returns wrapped "orchestrator config invalid" on bad config,
// without ever attempting to shell out. Confirms the guard kicks in
// before the channel is used so the close(events) defer still fires.
func TestOrchestrator_RunReturnsConfigErrorEarly(t *testing.T) {
	orch := &Orchestrator{} // empty — invalid

	events := make(chan server.TFApplyEvent, 4)
	err := orch.Run(context.Background(), "0123456789abcdef0123456789abcdef01234567", events)
	if err == nil {
		t.Fatal("Run on empty Orchestrator returned nil, want error")
	}
	if !strings.Contains(err.Error(), "config invalid") {
		t.Errorf("err = %q, want substring 'config invalid'", err.Error())
	}

	// events must be closed by defer in Run — a second receive must
	// return the zero value without blocking forever.
	select {
	case _, ok := <-events:
		if ok {
			t.Error("expected events channel closed; got value")
		}
	default:
		t.Error("events channel not closed; receive would block")
	}
}

// Run with a bogus repo URL surfaces a git error wrapped with the SHA
// for grep-ability. The streamCommand path is exercised end-to-end on
// a real git binary; this test asserts the error wrapping shape.
//
// Skipped if `git` is not on PATH (CI provides it; some sandboxed
// dev envs may not).
func TestOrchestrator_RunSurfacesGitFailure(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires git binary")
	}

	workdir := filepath.Join(t.TempDir(), "tf-work")
	orch := &Orchestrator{
		RepoURL: "https://example.invalid/does/not/exist.git",
		RootDir: "main/envs/staging-fastraid",
		WorkDir: workdir,
	}

	events := make(chan server.TFApplyEvent, 64)
	// Drain events in background so streamCommand doesn't block.
	go func() {
		for range events {
		}
	}()

	err := orch.Run(context.Background(), "0123456789abcdef0123456789abcdef01234567", events)
	if err == nil {
		t.Fatal("Run with bogus repo URL returned nil, want error")
	}
	if !strings.Contains(err.Error(), "git clone @") {
		t.Errorf("err = %q, want substring 'git clone @'", err.Error())
	}
}
