package main

import "testing"

// setMinimalEnv sets the env vars loadConfig requires so it returns without
// a "missing required env" error, letting a test assert defaults/overrides
// on optional fields.
func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYER_CERT_FILE", "/tmp/cert.pem")
	t.Setenv("DEPLOYER_KEY_FILE", "/tmp/key.pem")
	t.Setenv("DEPLOYER_REPOSITORY", "engram-app/engram-infra")
	t.Setenv("DEPLOYER_WORKFLOW_REF", "engram-app/engram-infra/.github/workflows/deploy.yml@refs/heads/main")
	t.Setenv("DEPLOYER_ALLOWED_IPS", "10.0.0.1")
}

// The plugin cache defaults to persistent Unraid appdata so a successful
// provider download survives reboots + per-run workdir wipes. /var/* is
// ephemeral on Unraid, so it must NOT be the default.
func TestLoadConfig_TFPluginCacheDirDefault(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := "/mnt/cache/appdata/engram-deployer/plugin-cache"
	if cfg.TFPluginCacheDir != want {
		t.Errorf("TFPluginCacheDir = %q, want %q", cfg.TFPluginCacheDir, want)
	}
}

// An operator can relocate the cache via env.
func TestLoadConfig_TFPluginCacheDirOverride(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("DEPLOYER_TF_PLUGIN_CACHE_DIR", "/custom/cache")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.TFPluginCacheDir != "/custom/cache" {
		t.Errorf("TFPluginCacheDir = %q, want %q", cfg.TFPluginCacheDir, "/custom/cache")
	}
}
