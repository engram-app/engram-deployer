package tfapply

import (
	"bufio"
	"context"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/engram-app/engram-deployer/internal/server"
)

// Orchestrator implements both server.TFApplier and server.TFPlanner by
// shelling out to git + terraform on the host. /tf-apply and /tf-plan
// share clone + init logic; only the final terraform invocation differs.
//
// All fields are required. Construct once at startup, reuse across
// requests — the server serializes apply + plan via applyMu so
// concurrent Run/Plan calls don't happen on the same workdir.
type Orchestrator struct {
	// TFBinary is the absolute or PATH-relative path to the terraform
	// binary. Defaults to "terraform" if empty.
	TFBinary string

	// GitBinary is the absolute or PATH-relative path to git. Defaults
	// to "git" if empty.
	GitBinary string

	// RepoURL is the HTTPS URL to clone. Pinned to one repo at startup
	// so a malicious /tf-apply caller can't redirect us elsewhere.
	RepoURL string

	// RootDir is the path within the repo containing the terraform
	// root to apply (e.g. "main/envs/staging-fastraid").
	RootDir string

	// WorkDir is the absolute path the daemon owns for cloning the
	// repo. Wiped + recreated every run for hermeticity.
	WorkDir string

	// Env is the additional environment for git + terraform
	// subprocesses (AWS creds, region, DOCKER_HOST). Merged on top of
	// the daemon's os.Environ() so PATH etc. are preserved.
	Env []string

	// TokenSource, when non-nil and RepoURL is https://github.com/...,
	// mints a fresh installation token before cloning and injects it
	// into the URL as `https://x-access-token:<token>@github.com/...`.
	// Nil means clone with whatever credentials git resolves on its
	// own (anonymous for public repos, key-based for SSH URLs).
	//
	// Interface (not concrete type) so tests can substitute fakes.
	TokenSource TokenSource
}

// TokenSource is the minimal contract Orchestrator needs to obtain a
// short-lived clone credential. Production uses AppTokenSource;
// tests use an in-process fake.
type TokenSource interface {
	Mint(ctx context.Context) (string, error)
}

// emitFn forwards a phase + line to whichever event channel the caller
// owns. Returns the typed events back through the closure so cloneAtSHA
// + tfInit + streamCommand don't care whether they're servicing an
// apply or a plan request.
type emitFn func(phase, msg string)

// Compile-time check that Orchestrator satisfies both server interfaces.
var (
	_ server.TFApplier = (*Orchestrator)(nil)
	_ server.TFPlanner = (*Orchestrator)(nil)
)

// Run performs the full apply cycle for sha. It MUST close events
// before returning so the HTTP handler's range loop terminates.
func (o *Orchestrator) Run(ctx context.Context, sha string, events chan<- server.TFApplyEvent) error {
	defer close(events)

	emit := func(phase, msg string) {
		select {
		case events <- server.TFApplyEvent{Phase: phase, Message: msg, Time: time.Now()}:
		case <-ctx.Done():
		}
	}

	rootPath, err := o.prepare(ctx, sha, emit)
	if err != nil {
		return err
	}

	if err := o.tfApply(ctx, rootPath, emit); err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}

	emit("done", "apply complete")
	return nil
}

// Plan performs init + plan for sha without mutating infra. Mirrors Run
// but stops after `terraform plan`. Plan output is streamed line-by-line
// through events under phase=tf_plan so the caller (typically a CI
// workflow) can collect it for a PR comment.
func (o *Orchestrator) Plan(ctx context.Context, sha string, events chan<- server.TFPlanEvent) error {
	defer close(events)

	emit := func(phase, msg string) {
		select {
		case events <- server.TFPlanEvent{Phase: phase, Message: msg, Time: time.Now()}:
		case <-ctx.Done():
		}
	}

	rootPath, err := o.prepare(ctx, sha, emit)
	if err != nil {
		return err
	}

	if err := o.tfPlan(ctx, rootPath, emit); err != nil {
		return fmt.Errorf("terraform plan: %w", err)
	}

	emit("done", "plan complete")
	return nil
}

// prepare clears the workdir, clones the repo at sha, runs terraform
// init, and returns the absolute path to the terraform root. Shared by
// Run + Plan; both need this exact prologue.
func (o *Orchestrator) prepare(ctx context.Context, sha string, emit emitFn) (string, error) {
	if err := o.validate(); err != nil {
		return "", fmt.Errorf("orchestrator config invalid: %w", err)
	}

	emit("git_fetch", fmt.Sprintf("preparing %s", o.WorkDir))
	if err := os.RemoveAll(o.WorkDir); err != nil {
		return "", fmt.Errorf("clear workdir: %w", err)
	}
	if err := os.MkdirAll(o.WorkDir, 0o700); err != nil {
		return "", fmt.Errorf("create workdir: %w", err)
	}

	if err := o.cloneAtSHA(ctx, sha, emit); err != nil {
		return "", fmt.Errorf("git clone @%s: %w", sha, err)
	}

	rootPath := filepath.Join(o.WorkDir, o.RootDir)
	if _, err := os.Stat(rootPath); err != nil {
		return "", fmt.Errorf("terraform root %s missing in repo @%s: %w", o.RootDir, sha, err)
	}

	if err := o.tfInit(ctx, rootPath, emit); err != nil {
		return "", fmt.Errorf("terraform init: %w", err)
	}
	return rootPath, nil
}

func (o *Orchestrator) validate() error {
	if o.RepoURL == "" {
		return fmt.Errorf("RepoURL is required")
	}
	if o.RootDir == "" {
		return fmt.Errorf("RootDir is required")
	}
	if o.WorkDir == "" {
		return fmt.Errorf("WorkDir is required")
	}
	return nil
}

func (o *Orchestrator) gitBin() string {
	if o.GitBinary != "" {
		return o.GitBinary
	}
	return "git"
}

func (o *Orchestrator) tfBin() string {
	if o.TFBinary != "" {
		return o.TFBinary
	}
	return "terraform"
}

// cloneAtSHA shallow-clones the repo and checks out exactly sha. Two
// git invocations rather than one `git clone --depth 1 <branch>` so we
// pin to SHA, not a branch tip that could shift between PR merge and
// our checkout.
//
// If TokenSource is set and RepoURL is an https://github.com/... URL,
// mints a short-lived App installation token and injects it as basic
// auth in the URL. The token never reaches the events stream — only
// the redacted form of the URL appears in event messages.
func (o *Orchestrator) cloneAtSHA(ctx context.Context, sha string, emit emitFn) error {
	cloneURL, err := o.resolveCloneURL(ctx)
	if err != nil {
		return fmt.Errorf("resolve clone URL: %w", err)
	}

	clone := exec.CommandContext(ctx, o.gitBin(),
		"clone", "--filter=blob:none", "--no-checkout", cloneURL, o.WorkDir,
	)
	clone.Env = o.fullEnv()
	if err := streamCommand(ctx, clone, "git_fetch", emit); err != nil {
		return err
	}

	checkout := exec.CommandContext(ctx, o.gitBin(),
		"-C", o.WorkDir, "checkout", "--detach", sha,
	)
	checkout.Env = o.fullEnv()
	return streamCommand(ctx, checkout, "git_fetch", emit)
}

// resolveCloneURL returns the URL to pass to `git clone`. If TokenSource
// is set and RepoURL is https://github.com/..., mints a fresh
// installation token and embeds it as `x-access-token` basic auth.
// Otherwise returns RepoURL unchanged.
func (o *Orchestrator) resolveCloneURL(ctx context.Context) (string, error) {
	if o.TokenSource == nil {
		return o.RepoURL, nil
	}
	if !strings.HasPrefix(o.RepoURL, "https://github.com/") {
		// TokenSource only helps for HTTPS GitHub URLs.
		return o.RepoURL, nil
	}

	tok, err := o.TokenSource.Mint(ctx)
	if err != nil {
		return "", fmt.Errorf("mint App token: %w", err)
	}

	parsed, err := neturl.Parse(o.RepoURL)
	if err != nil {
		return "", fmt.Errorf("parse RepoURL: %w", err)
	}
	parsed.User = neturl.UserPassword("x-access-token", tok)
	return parsed.String(), nil
}

// tfInit runs `terraform init`, retrying only transient network failures
// (provider/module downloads) per withInitRetry. init is read-only and
// runs before any mutation, so retrying it is safe — unlike apply, which
// is never retried (a dropped connection mid-apply could double-apply).
//
// Each attempt captures the combined output alongside streaming it so a
// failure can be classified. TF_PLUGIN_CACHE_DIR (injected via Env at
// startup) means a successful prior download is reused, shrinking the
// network surface that can blip in the first place.
func (o *Orchestrator) tfInit(ctx context.Context, rootPath string, emit emitFn) error {
	return withInitRetry(ctx, emit, sleepCtx, func(attempt int) (string, error) {
		capEmit, snapshot := newCapturingEmit(emit)
		cmd := exec.CommandContext(ctx, o.tfBin(),
			"-chdir="+rootPath, "init", "-input=false", "-no-color",
		)
		cmd.Env = o.fullEnv()
		err := streamCommand(ctx, cmd, "tf_init", capEmit)
		return snapshot(), err
	})
}

func (o *Orchestrator) tfApply(ctx context.Context, rootPath string, emit emitFn) error {
	cmd := exec.CommandContext(ctx, o.tfBin(),
		"-chdir="+rootPath, "apply", "-input=false", "-auto-approve", "-no-color",
	)
	cmd.Env = o.fullEnv()
	return streamCommand(ctx, cmd, "tf_apply", emit)
}

// tfPlan runs `terraform plan` without -detailed-exitcode: we want
// exit 0 on "plan succeeded with or without diff", and a non-zero exit
// only on actual error (auth, syntax, missing provider). The reviewer
// reads the streamed plan output and judges the diff.
func (o *Orchestrator) tfPlan(ctx context.Context, rootPath string, emit emitFn) error {
	cmd := exec.CommandContext(ctx, o.tfBin(),
		"-chdir="+rootPath, "plan", "-input=false", "-no-color", "-lock-timeout=60s",
	)
	cmd.Env = o.fullEnv()
	return streamCommand(ctx, cmd, "tf_plan", emit)
}

func (o *Orchestrator) fullEnv() []string {
	base := os.Environ()
	return append(base, o.Env...)
}

// streamCommand runs cmd with combined stdout+stderr forwarded line by
// line to emit under the given phase. Returns the command's exit
// error (with output context for diagnosis).
func streamCommand(ctx context.Context, cmd *exec.Cmd, phase string, emit emitFn) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", cmd.Path, err)
	}

	done := make(chan struct{}, 2)
	go pipeLines(ctx, stdoutPipe, phase, emit, done)
	go pipeLines(ctx, stderrPipe, phase, emit, done)
	<-done
	<-done

	return cmd.Wait()
}

func pipeLines(ctx context.Context, r io.Reader, phase string, emit emitFn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		emit(phase, line)
		if ctx.Err() != nil {
			return
		}
	}
}
