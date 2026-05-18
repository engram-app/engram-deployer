package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig pins every GitHub Actions OIDC claim we care about.
// Tokens whose claims don't match exactly are rejected.
//
// For push-event tokens (e.g. /deploy, /tf-apply) Ref + WorkflowRef pin
// exact strings. For pull_request-event tokens (e.g. /tf-plan) those
// claims vary per PR — use Subject (`sub` claim, constant across PRs in
// a repo) + WorkflowRefPrefix instead, leaving Ref + WorkflowRef empty.
type OIDCConfig struct {
	JWKSURL     string // GitHub's: https://token.actions.githubusercontent.com/.well-known/jwks
	Issuer      string // https://token.actions.githubusercontent.com
	Audience    string // engram-deploy
	Repository  string // e.g. engram-app/Engram
	Ref         string // exact match if non-empty
	WorkflowRef string // exact match if non-empty

	// Subject pins the `sub` claim exactly when non-empty. For PR-event
	// tokens use `repo:<owner>/<repo>:pull_request`.
	Subject string

	// WorkflowRefPrefix pins workflow_ref by prefix match when WorkflowRef
	// is empty. Use the path up through `<workflow>.yml@` so any ref
	// suffix (e.g. refs/pull/N/merge) is accepted.
	WorkflowRefPrefix string
}

// Claims is the subset of GitHub Actions OIDC claims callers need
// post-validation (currently just the JTI, used for replay tracking).
type Claims struct {
	JTI string
}

// Validator verifies OIDC JWTs against GitHub's JWKS and an allowlist
// of pinned claims.
type Validator struct {
	cfg     OIDCConfig
	keyfunc jwt.Keyfunc
}

// NewValidator fetches the JWKS once at construction. Subsequent JWKS
// refreshes are managed by the keyfunc package.
//
// Rejects configs that leave both Ref+Subject empty or both
// WorkflowRef+WorkflowRefPrefix empty — those would silently accept any
// value for the corresponding claim.
func NewValidator(ctx context.Context, cfg OIDCConfig) (*Validator, error) {
	if cfg.Ref == "" && cfg.Subject == "" {
		return nil, errors.New("OIDCConfig requires Ref or Subject (both empty would skip the binding)")
	}
	if cfg.WorkflowRef == "" && cfg.WorkflowRefPrefix == "" {
		return nil, errors.New("OIDCConfig requires WorkflowRef or WorkflowRefPrefix (both empty would skip the binding)")
	}
	k, err := keyfunc.NewDefaultCtx(ctx, []string{cfg.JWKSURL})
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", cfg.JWKSURL, err)
	}
	return &Validator{cfg: cfg, keyfunc: k.Keyfunc}, nil
}

// Validate parses and verifies tokenStr. Returns parsed claims on success.
// Any failure (bad signature, wrong claim, expired, ...) returns an error
// and the caller MUST refuse the request.
func (v *Validator) Validate(tokenStr string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
	)

	parsed, err := parser.Parse(tokenStr, v.keyfunc)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("claims not a map")
	}

	if err := v.checkClaim(mc, "repository", v.cfg.Repository); err != nil {
		return nil, err
	}
	if v.cfg.Ref != "" {
		if err := v.checkClaim(mc, "ref", v.cfg.Ref); err != nil {
			return nil, err
		}
	}
	if v.cfg.Subject != "" {
		if err := v.checkClaim(mc, "sub", v.cfg.Subject); err != nil {
			return nil, err
		}
	}
	if v.cfg.WorkflowRef != "" {
		if err := v.checkClaim(mc, "workflow_ref", v.cfg.WorkflowRef); err != nil {
			return nil, err
		}
	} else {
		got, _ := mc["workflow_ref"].(string)
		if !strings.HasPrefix(got, v.cfg.WorkflowRefPrefix) {
			return nil, fmt.Errorf("claim %q = %q, want prefix %q", "workflow_ref", got, v.cfg.WorkflowRefPrefix)
		}
	}

	jti, _ := mc["jti"].(string)
	if jti == "" {
		return nil, errors.New("token missing jti claim")
	}

	return &Claims{JTI: jti}, nil
}

func (v *Validator) checkClaim(mc jwt.MapClaims, key, expected string) error {
	got, _ := mc[key].(string)
	if got != expected {
		return fmt.Errorf("claim %q = %q, want %q", key, got, expected)
	}
	return nil
}
