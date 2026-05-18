package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/engram-app/engram-deployer/internal/auth"
	"github.com/engram-app/engram-deployer/internal/oidctest"
	"github.com/golang-jwt/jwt/v5"
)

// fakeDeployer captures Run invocations and emits a scripted sequence
// of events, optionally followed by an error.
type fakeDeployer struct {
	mu         sync.Mutex
	calledWith string
	scriptEvts []DeployEvent
	scriptErr  error
}

func (f *fakeDeployer) Run(_ context.Context, version string, events chan<- DeployEvent) error {
	f.mu.Lock()
	f.calledWith = version
	evs := append([]DeployEvent(nil), f.scriptEvts...)
	err := f.scriptErr
	f.mu.Unlock()

	for _, e := range evs {
		events <- e
	}
	close(events)
	return err
}

func (f *fakeDeployer) CalledWith() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calledWith
}

// fakeTFApplier mirrors fakeDeployer for /tf-apply.
type fakeTFApplier struct {
	mu         sync.Mutex
	calledWith string
	scriptEvts []TFApplyEvent
	scriptErr  error
}

func (f *fakeTFApplier) Run(_ context.Context, sha string, events chan<- TFApplyEvent) error {
	f.mu.Lock()
	f.calledWith = sha
	evs := append([]TFApplyEvent(nil), f.scriptEvts...)
	err := f.scriptErr
	f.mu.Unlock()

	for _, e := range evs {
		events <- e
	}
	close(events)
	return err
}

func (f *fakeTFApplier) CalledWith() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calledWith
}

// fakeTFPlanner mirrors fakeTFApplier for /tf-plan.
type fakeTFPlanner struct {
	mu         sync.Mutex
	calledWith string
	scriptEvts []TFPlanEvent
	scriptErr  error
}

func (f *fakeTFPlanner) Plan(_ context.Context, sha string, events chan<- TFPlanEvent) error {
	f.mu.Lock()
	f.calledWith = sha
	evs := append([]TFPlanEvent(nil), f.scriptEvts...)
	err := f.scriptErr
	f.mu.Unlock()

	for _, e := range evs {
		events <- e
	}
	close(events)
	return err
}

func (f *fakeTFPlanner) CalledWith() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calledWith
}

// testServerOpts is configured via the functional opts passed to newTestServer.
type testServerOpts struct {
	deployer Deployer

	// wireTFApply toggles whether /tf-apply is wired. Default off so
	// existing /deploy tests don't pull in tf-apply machinery.
	wireTFApply bool
	tfApplier   TFApplier

	wireTFPlan bool
	tfPlanner  TFPlanner
}

func withDeployer(d Deployer) func(*testServerOpts) {
	return func(o *testServerOpts) { o.deployer = d }
}

func withTFApplier(a TFApplier) func(*testServerOpts) {
	return func(o *testServerOpts) {
		o.wireTFApply = true
		o.tfApplier = a
	}
}

func withTFPlanner(p TFPlanner) func(*testServerOpts) {
	return func(o *testServerOpts) {
		o.wireTFPlan = true
		o.tfPlanner = p
	}
}

// newTestServer constructs a Server wired to the in-process OIDC test issuer
// (oidctest.Shared) and a fake Deployer. Caller can override the deployer
// with withDeployer, or wire /tf-apply with withTFApplier.
func newTestServer(t *testing.T, opts ...func(*testServerOpts)) *Server {
	t.Helper()

	o := &testServerOpts{deployer: &fakeDeployer{}}
	for _, opt := range opts {
		opt(o)
	}

	iss := oidctest.Shared(t)
	validator, err := auth.NewValidator(context.Background(), auth.OIDCConfig{
		JWKSURL:     iss.JWKSURL(),
		Issuer:      "https://token.actions.githubusercontent.com",
		Audience:    "engram-deploy",
		Repository:  "engram-app/Engram",
		Ref:         "refs/heads/main",
		WorkflowRef: "engram-app/Engram/.github/workflows/ci.yml@refs/heads/main",
	})
	if err != nil {
		t.Fatalf("validator init: %v", err)
	}

	ipAllow, err := auth.NewIPAllowlist([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("ip allowlist init: %v", err)
	}

	cfg := Config{
		Validator: validator,
		JTI:       auth.NewJTISet(100, 30*time.Minute),
		IPAllow:   ipAllow,
		Deployer:  o.deployer,
	}

	if o.wireTFApply {
		tfValidator, err := auth.NewValidator(context.Background(), auth.OIDCConfig{
			JWKSURL:     iss.JWKSURL(),
			Issuer:      "https://token.actions.githubusercontent.com",
			Audience:    "engram-tf-apply",
			Repository:  "engram-app/engram-infra",
			Ref:         "refs/heads/main",
			WorkflowRef: "engram-app/engram-infra/.github/workflows/tf-apply.yml@refs/heads/main",
		})
		if err != nil {
			t.Fatalf("tf-apply validator init: %v", err)
		}
		cfg.TFApplyValidator = tfValidator
		if o.tfApplier == nil {
			o.tfApplier = &fakeTFApplier{}
		}
		cfg.TFApplier = o.tfApplier
	}

	if o.wireTFPlan {
		planValidator, err := auth.NewValidator(context.Background(), auth.OIDCConfig{
			JWKSURL:           iss.JWKSURL(),
			Issuer:            "https://token.actions.githubusercontent.com",
			Audience:          "engram-tf-plan",
			Repository:        "engram-app/engram-infra",
			Subject:           "repo:engram-app/engram-infra:pull_request",
			WorkflowRefPrefix: "engram-app/engram-infra/.github/workflows/tf-plan.yml@",
		})
		if err != nil {
			t.Fatalf("tf-plan validator init: %v", err)
		}
		cfg.TFPlanValidator = planValidator
		if o.tfPlanner == nil {
			o.tfPlanner = &fakeTFPlanner{}
		}
		cfg.TFPlanner = o.tfPlanner
	}

	return New(cfg)
}

// mintValidToken returns a freshly-signed OIDC token whose claims pass
// every validator gate. Use a unique jti per test run to avoid replay
// collisions across calls that share an issuer.
func mintValidToken(t *testing.T, jti string) string {
	t.Helper()
	iss := oidctest.Shared(t)
	now := time.Now()
	return iss.Mint(t, jwt.MapClaims{
		"iss":          "https://token.actions.githubusercontent.com",
		"aud":          "engram-deploy",
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"exp":          now.Add(15 * time.Minute).Unix(),
		"jti":          jti,
		"repository":   "engram-app/Engram",
		"ref":          "refs/heads/main",
		"workflow_ref": "engram-app/Engram/.github/workflows/ci.yml@refs/heads/main",
	})
}

// mintValidTFPlanToken returns a freshly-signed OIDC token whose claims
// pass the /tf-plan validator gate (PR-event token: distinct audience,
// pull_request subject, workflow_ref matching the tf-plan.yml prefix,
// ref bearing a pull/N/merge format).
func mintValidTFPlanToken(t *testing.T, jti string) string {
	t.Helper()
	iss := oidctest.Shared(t)
	now := time.Now()
	return iss.Mint(t, jwt.MapClaims{
		"iss":          "https://token.actions.githubusercontent.com",
		"aud":          "engram-tf-plan",
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"exp":          now.Add(15 * time.Minute).Unix(),
		"jti":          jti,
		"repository":   "engram-app/engram-infra",
		"ref":          "repo:engram-app/engram-infra:pull_request",
		"sub":          "repo:engram-app/engram-infra:pull_request",
		"workflow_ref": "engram-app/engram-infra/.github/workflows/tf-plan.yml@refs/pull/42/merge",
	})
}

// mintValidTFApplyToken returns a freshly-signed OIDC token whose claims
// pass the /tf-apply validator gate (different audience + repo +
// workflow_ref pin than /deploy).
func mintValidTFApplyToken(t *testing.T, jti string) string {
	t.Helper()
	iss := oidctest.Shared(t)
	now := time.Now()
	return iss.Mint(t, jwt.MapClaims{
		"iss":          "https://token.actions.githubusercontent.com",
		"aud":          "engram-tf-apply",
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"exp":          now.Add(15 * time.Minute).Unix(),
		"jti":          jti,
		"repository":   "engram-app/engram-infra",
		"ref":          "refs/heads/main",
		"workflow_ref": "engram-app/engram-infra/.github/workflows/tf-apply.yml@refs/heads/main",
	})
}
