package tfapply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verify hard-fails on missing required fields and on a missing PEM
// path. Used at daemon startup so misconfigured installs fail loud.
func TestAppTokenSource_Verify(t *testing.T) {
	cases := []struct {
		name   string
		src    AppTokenSource
		want   string
		preFn  func(t *testing.T, src *AppTokenSource)
		postFn func()
	}{
		{
			name: "missing AppID",
			src:  AppTokenSource{InstallationID: "x", PEMPath: "/tmp/x"},
			want: "AppID",
		},
		{
			name: "missing InstallationID",
			src:  AppTokenSource{AppID: "x", PEMPath: "/tmp/x"},
			want: "InstallationID",
		},
		{
			name: "missing PEMPath",
			src:  AppTokenSource{AppID: "x", InstallationID: "x"},
			want: "PEMPath",
		},
		{
			name: "PEM file missing",
			src:  AppTokenSource{AppID: "x", InstallationID: "x", PEMPath: "/tmp/does-not-exist-12345"},
			want: "PEM file",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.src.Verify()
			if err == nil {
				t.Fatal("Verify returned nil, want error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.want)
			}
		})
	}
}

// Verify accepts a configured source with an existing PEM file
// (contents not validated at Verify time — that happens at Mint).
func TestAppTokenSource_VerifyAcceptsExistingPEM(t *testing.T) {
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "fake.pem")
	if err := os.WriteFile(pemPath, []byte("not-a-real-pem-but-file-exists"), 0o600); err != nil {
		t.Fatalf("write fake PEM: %v", err)
	}

	src := AppTokenSource{
		AppID:          "12345",
		InstallationID: "67890",
		PEMPath:        pemPath,
	}
	if err := src.Verify(); err != nil {
		t.Errorf("Verify returned %v, want nil", err)
	}
}
