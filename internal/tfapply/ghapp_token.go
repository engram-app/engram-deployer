package tfapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppTokenSource mints GitHub App installation tokens on demand.
//
// Each Mint hits the GitHub API for a fresh token. No caching since
// /tf-apply runs at low frequency (release cadence) and tokens are
// 1-hour scoped — a fresh-per-request model is simpler than a cache
// with TTL bookkeeping.
//
// The minted token can be plumbed into an HTTPS clone URL as
//
//	https://x-access-token:<token>@github.com/<owner>/<repo>.git
//
// GitHub recognizes that form as App-installation authentication.
type AppTokenSource struct {
	AppID          string // GH App ID, e.g. "3743326"
	InstallationID string // installation ID for the engram-app org
	PEMPath        string // absolute path to the App's private key PEM

	// HTTPClient is used to call the GitHub API. Defaulted in Mint when nil
	// so tests can substitute a fake.
	HTTPClient *http.Client
}

// Verify is a cheap pre-flight: confirms the source is configured and
// the PEM file is readable. Does NOT hit the API.
func (s *AppTokenSource) Verify() error {
	if s.AppID == "" {
		return errors.New("AppID is required")
	}
	if s.InstallationID == "" {
		return errors.New("InstallationID is required")
	}
	if s.PEMPath == "" {
		return errors.New("PEMPath is required")
	}
	if _, err := os.Stat(s.PEMPath); err != nil {
		return fmt.Errorf("PEM file: %w", err)
	}
	return nil
}

// Mint returns a short-lived (~1 hour) GitHub App installation token.
// Each call signs a fresh App JWT, exchanges it at
// /app/installations/<id>/access_tokens, and returns the resulting
// access token string.
func (s *AppTokenSource) Mint(ctx context.Context) (string, error) {
	if err := s.Verify(); err != nil {
		return "", err
	}

	pemBytes, err := os.ReadFile(s.PEMPath)
	if err != nil {
		return "", fmt.Errorf("read PEM: %w", err)
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return "", fmt.Errorf("parse PEM: %w", err)
	}

	// App JWT: iss=app_id, iat slightly in the past to tolerate clock
	// skew, exp <= iat+10min per GitHub's documented constraint.
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    s.AppID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	})
	appJWT, err := tok.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("sign App JWT: %w", err)
	}

	url := fmt.Sprintf(
		"https://api.github.com/app/installations/%s/access_tokens",
		s.InstallationID,
	)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("github api %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.Token == "" {
		return "", errors.New("github api returned no token")
	}
	return out.Token, nil
}
