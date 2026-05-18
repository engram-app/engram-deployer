package tfapply

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// resolveCloneURL passes URLs through unchanged when TokenSource is nil
// — public repos work the same with or without the new code path.
func TestResolveCloneURL_NoTokenSource(t *testing.T) {
	o := &Orchestrator{RepoURL: "https://github.com/owner/repo.git"}
	got, err := o.resolveCloneURL(context.Background())
	if err != nil {
		t.Fatalf("resolveCloneURL: %v", err)
	}
	if got != o.RepoURL {
		t.Errorf("got %q, want %q (URL must be unchanged when TokenSource nil)", got, o.RepoURL)
	}
}

// SSH URLs are passed through unchanged even when TokenSource is set —
// the x-access-token trick only works for HTTPS GitHub URLs. SSH URLs
// rely on the daemon's GIT_SSH_COMMAND / ~/.ssh setup instead.
func TestResolveCloneURL_SSHURLUnchanged(t *testing.T) {
	o := &Orchestrator{
		RepoURL: "git@github.com:owner/repo.git",
		TokenSource: &fakeTokenSource{
			token: "ghs_FAKE",
		},
	}
	got, err := o.resolveCloneURL(context.Background())
	if err != nil {
		t.Fatalf("resolveCloneURL: %v", err)
	}
	if got != o.RepoURL {
		t.Errorf("got %q, want %q (SSH URLs must skip token injection)", got, o.RepoURL)
	}
}

// Non-github HTTPS URLs are also passed through unchanged — the
// x-access-token form is GitHub-specific.
func TestResolveCloneURL_NonGitHubHTTPSUnchanged(t *testing.T) {
	o := &Orchestrator{
		RepoURL: "https://gitlab.example.com/owner/repo.git",
		TokenSource: &fakeTokenSource{
			token: "ghs_FAKE",
		},
	}
	got, err := o.resolveCloneURL(context.Background())
	if err != nil {
		t.Fatalf("resolveCloneURL: %v", err)
	}
	if got != o.RepoURL {
		t.Errorf("got %q, want %q (non-GitHub HTTPS must skip token injection)", got, o.RepoURL)
	}
}

// HTTPS GitHub URLs get the token injected as x-access-token basic
// auth. Verifies the URL shape; the token value MUST appear once, in
// the password position, and ONLY once (no echoing into path/query).
func TestResolveCloneURL_HTTPSGitHubInjectsToken(t *testing.T) {
	o := &Orchestrator{
		RepoURL: "https://github.com/engram-app/engram-infra.git",
		TokenSource: &fakeTokenSource{
			token: "ghs_TESTTOKEN",
		},
	}
	got, err := o.resolveCloneURL(context.Background())
	if err != nil {
		t.Fatalf("resolveCloneURL: %v", err)
	}

	wantPrefix := "https://x-access-token:ghs_TESTTOKEN@github.com/engram-app/engram-infra.git"
	if got != wantPrefix {
		t.Errorf("got %q, want %q", got, wantPrefix)
	}

	// Token appears exactly once in the URL — neither leaked into query
	// string nor double-substituted.
	if strings.Count(got, "ghs_TESTTOKEN") != 1 {
		t.Errorf("token appeared %d times, want 1: %q", strings.Count(got, "ghs_TESTTOKEN"), got)
	}
}

// If the TokenSource Mint fails, the error propagates up — we MUST NOT
// fall back to a tokenless clone and risk leaking the failure as a
// "public repo cloned anonymously" surprise.
func TestResolveCloneURL_MintFailurePropagates(t *testing.T) {
	o := &Orchestrator{
		RepoURL: "https://github.com/engram-app/engram-infra.git",
		TokenSource: &fakeTokenSource{
			mintErr: errors.New("forced fail"),
		},
	}
	_, err := o.resolveCloneURL(context.Background())
	if err == nil {
		t.Fatal("resolveCloneURL returned nil, want error")
	}
	if !strings.Contains(err.Error(), "forced fail") {
		t.Errorf("err = %q, want substring 'forced fail'", err.Error())
	}
}

// fakeTokenSource lets resolveCloneURL tests skip the real GitHub API
// + PEM-parsing pipeline. It satisfies the same Mint signature.
type fakeTokenSource struct {
	token   string
	mintErr error
}

// Mint matches AppTokenSource.Mint but skips HTTP/JWT entirely.
func (f *fakeTokenSource) Mint(ctx context.Context) (string, error) {
	if f.mintErr != nil {
		return "", f.mintErr
	}
	return f.token, nil
}

// Verify is a no-op for the fake.
func (f *fakeTokenSource) Verify() error { return nil }
