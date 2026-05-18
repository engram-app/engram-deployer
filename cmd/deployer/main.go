// Command engram-deployer is the pull-based deploy daemon for Engram on
// FastRaid. See README.md and internal/server/doc.go for the full picture.
//
// Config is loaded from environment variables (set by the Unraid plugin's
// rc.d wrapper).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/engram-app/engram-deployer/internal/auth"
	"github.com/engram-app/engram-deployer/internal/deploy"
	"github.com/engram-app/engram-deployer/internal/server"
	"github.com/engram-app/engram-deployer/internal/tfapply"
)

type config struct {
	Addr        string
	CertFile    string
	KeyFile     string
	JWKSURL     string
	Issuer      string
	Audience    string
	Repository  string
	Ref         string
	WorkflowRef string
	AllowedIPs  []string

	Image               string
	TemplateDir         string
	DockerPath          string
	UpdateContainerPath string
	HealthPollInterval  time.Duration
	HealthMaxWait       time.Duration

	// tf-apply config — all optional. The /tf-apply endpoint is wired
	// only when TFApplyRepository + TFApplyWorkflowRef + TFApplyRootDir
	// are all set (validated in loadConfig).
	TFApplyRepository  string
	TFApplyRef         string
	TFApplyWorkflowRef string
	TFApplyAudience    string
	TFApplyRepoURL     string
	TFApplyRootDir     string
	TFApplyWorkDir     string
	TFBinaryPath       string
	TFGitBinaryPath    string
	TFAWSAccessKeyID   string
	TFAWSSecretKey     string
	TFAWSRegion        string
	TFDockerHost       string

	// tf-plan piggybacks on tf-apply: same repo, same root, same AWS
	// creds, same Orchestrator. Only the OIDC validator differs (PR
	// events have a different audience + sub claim).
	TFPlanAudience     string
	TFPlanWorkflowFile string

	// GitHub App credentials for minting installation tokens used to
	// clone private engram-infra. All three required when tf-apply is
	// enabled AND the repo URL is https://github.com/... (any other
	// URL bypasses App-token minting; daemon clones with whatever
	// credentials git can resolve).
	TFAppID             string
	TFAppInstallationID string
	TFAppPEMPath        string
}

func loadConfig() (config, error) {
	cfg := config{
		Addr:        envOr("DEPLOYER_ADDR", ":8443"),
		CertFile:    os.Getenv("DEPLOYER_CERT_FILE"),
		KeyFile:     os.Getenv("DEPLOYER_KEY_FILE"),
		JWKSURL:     envOr("DEPLOYER_JWKS_URL", "https://token.actions.githubusercontent.com/.well-known/jwks"),
		Issuer:      envOr("DEPLOYER_ISSUER", "https://token.actions.githubusercontent.com"),
		Audience:    envOr("DEPLOYER_AUDIENCE", "engram-deploy"),
		Repository:  os.Getenv("DEPLOYER_REPOSITORY"),
		Ref:         envOr("DEPLOYER_REF", "refs/heads/main"),
		WorkflowRef: os.Getenv("DEPLOYER_WORKFLOW_REF"),
		AllowedIPs:  splitCSV(os.Getenv("DEPLOYER_ALLOWED_IPS")),

		Image:               envOr("DEPLOYER_IMAGE", "ghcr.io/engram-app/engram"),
		TemplateDir:         envOr("DEPLOYER_TEMPLATE_DIR", "/boot/config/plugins/dockerMan/templates-user"),
		DockerPath:          envOr("DEPLOYER_DOCKER_PATH", "docker"),
		UpdateContainerPath: envOr("DEPLOYER_UPDATE_CONTAINER_PATH", deploy.DefaultUpdateContainerPath),
		HealthPollInterval:  envDuration("DEPLOYER_HEALTH_POLL_INTERVAL", 2*time.Second),
		HealthMaxWait:       envDuration("DEPLOYER_HEALTH_MAX_WAIT", 60*time.Second),

		TFApplyRepository:  os.Getenv("DEPLOYER_TF_APPLY_REPOSITORY"),
		TFApplyRef:         envOr("DEPLOYER_TF_APPLY_REF", "refs/heads/main"),
		TFApplyWorkflowRef: os.Getenv("DEPLOYER_TF_APPLY_WORKFLOW_REF"),
		TFApplyAudience:    envOr("DEPLOYER_TF_APPLY_AUDIENCE", "engram-tf-apply"),
		TFApplyRepoURL:     envOr("DEPLOYER_TF_APPLY_REPO_URL", "https://github.com/engram-app/engram-infra.git"),
		TFApplyRootDir:     os.Getenv("DEPLOYER_TF_APPLY_ROOT_DIR"),
		TFApplyWorkDir:     envOr("DEPLOYER_TF_APPLY_WORKDIR", "/var/lib/engram-deployer/tf"),
		TFBinaryPath:       envOr("DEPLOYER_TF_BINARY_PATH", "terraform"),
		TFGitBinaryPath:    envOr("DEPLOYER_TF_GIT_BINARY_PATH", "git"),
		TFAWSAccessKeyID:   os.Getenv("DEPLOYER_TF_AWS_ACCESS_KEY_ID"),
		TFAWSSecretKey:     os.Getenv("DEPLOYER_TF_AWS_SECRET_ACCESS_KEY"),
		TFAWSRegion:        envOr("DEPLOYER_TF_AWS_REGION", "us-east-1"),
		TFDockerHost:       envOr("DEPLOYER_TF_DOCKER_HOST", "unix:///var/run/docker.sock"),

		TFAppID:             os.Getenv("DEPLOYER_TF_APPLY_GH_APP_ID"),
		TFAppInstallationID: os.Getenv("DEPLOYER_TF_APPLY_GH_APP_INSTALLATION_ID"),
		TFAppPEMPath:        os.Getenv("DEPLOYER_TF_APPLY_GH_APP_PEM_PATH"),

		TFPlanAudience:     envOr("DEPLOYER_TF_PLAN_AUDIENCE", "engram-tf-plan"),
		TFPlanWorkflowFile: envOr("DEPLOYER_TF_PLAN_WORKFLOW_FILE", "tf-plan.yml"),
	}
	var missing []string
	if cfg.CertFile == "" {
		missing = append(missing, "DEPLOYER_CERT_FILE")
	}
	if cfg.KeyFile == "" {
		missing = append(missing, "DEPLOYER_KEY_FILE")
	}
	if cfg.Repository == "" {
		missing = append(missing, "DEPLOYER_REPOSITORY")
	}
	if cfg.WorkflowRef == "" {
		missing = append(missing, "DEPLOYER_WORKFLOW_REF")
	}
	if len(cfg.AllowedIPs) == 0 {
		missing = append(missing, "DEPLOYER_ALLOWED_IPS")
	}

	// tf-apply enablement is all-or-nothing: if any one of the three
	// core knobs is set, the rest must also be set, including AWS
	// creds. Empty + empty + empty = endpoint disabled cleanly.
	if cfg.tfApplyEnabled() {
		var tfMissing []string
		if cfg.TFApplyRepository == "" {
			tfMissing = append(tfMissing, "DEPLOYER_TF_APPLY_REPOSITORY")
		}
		if cfg.TFApplyWorkflowRef == "" {
			tfMissing = append(tfMissing, "DEPLOYER_TF_APPLY_WORKFLOW_REF")
		}
		if cfg.TFApplyRootDir == "" {
			tfMissing = append(tfMissing, "DEPLOYER_TF_APPLY_ROOT_DIR")
		}
		if cfg.TFAWSAccessKeyID == "" {
			tfMissing = append(tfMissing, "DEPLOYER_TF_AWS_ACCESS_KEY_ID")
		}
		if cfg.TFAWSSecretKey == "" {
			tfMissing = append(tfMissing, "DEPLOYER_TF_AWS_SECRET_ACCESS_KEY")
		}
		// App credentials required when cloning private https://github.com/...
		// repos. If the operator points at a public repo or SSH URL, all
		// three may be empty (the daemon will not try to mint a token).
		if strings.HasPrefix(cfg.TFApplyRepoURL, "https://github.com/") {
			if cfg.TFAppID == "" {
				tfMissing = append(tfMissing, "DEPLOYER_TF_APPLY_GH_APP_ID")
			}
			if cfg.TFAppInstallationID == "" {
				tfMissing = append(tfMissing, "DEPLOYER_TF_APPLY_GH_APP_INSTALLATION_ID")
			}
			if cfg.TFAppPEMPath == "" {
				tfMissing = append(tfMissing, "DEPLOYER_TF_APPLY_GH_APP_PEM_PATH")
			}
		}
		if len(tfMissing) > 0 {
			missing = append(missing, tfMissing...)
		}
	}

	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required env: %v", missing)
	}
	return cfg, nil
}

// tfApplyEnabled reports whether ANY tf-apply env var indicates the
// operator wants /tf-apply wired. Partial config is an error caught by
// loadConfig — this method just flags presence.
func (c config) tfApplyEnabled() bool {
	return c.TFApplyRepository != "" ||
		c.TFApplyWorkflowRef != "" ||
		c.TFApplyRootDir != "" ||
		c.TFAWSAccessKeyID != "" ||
		c.TFAWSSecretKey != ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	validator, err := auth.NewValidator(ctx, auth.OIDCConfig{
		JWKSURL:     cfg.JWKSURL,
		Issuer:      cfg.Issuer,
		Audience:    cfg.Audience,
		Repository:  cfg.Repository,
		Ref:         cfg.Ref,
		WorkflowRef: cfg.WorkflowRef,
	})
	if err != nil {
		log.Fatalf("init OIDC validator: %v", err)
	}

	ipAllow, err := auth.NewIPAllowlist(cfg.AllowedIPs)
	if err != nil {
		log.Fatalf("init IP allowlist: %v", err)
	}

	orch := &deploy.Orchestrator{
		Image:       cfg.Image,
		TemplateDir: cfg.TemplateDir,
		// Order matters — SaaS first so a broken image fails fast on the
		// lower-traffic side without touching production-facing selfhost.
		Containers: []deploy.ContainerSpec{
			{Name: "engram-saas", Port: 8000},
			{Name: "engram-selfhost", Port: 8001},
		},
		Puller:  &deploy.Docker{Path: cfg.DockerPath},
		Updater: deploy.NewUpdateContainer(cfg.UpdateContainerPath),
		Health:  deploy.NewHealthChecker(cfg.HealthPollInterval, cfg.HealthMaxWait),
	}

	srvCfg := server.Config{
		Validator: validator,
		JTI:       auth.NewJTISet(1000, 30*time.Minute),
		IPAllow:   ipAllow,
		Deployer:  orch,
	}

	if cfg.tfApplyEnabled() {
		tfValidator, err := auth.NewValidator(ctx, auth.OIDCConfig{
			JWKSURL:     cfg.JWKSURL,
			Issuer:      cfg.Issuer,
			Audience:    cfg.TFApplyAudience,
			Repository:  cfg.TFApplyRepository,
			Ref:         cfg.TFApplyRef,
			WorkflowRef: cfg.TFApplyWorkflowRef,
		})
		if err != nil {
			log.Fatalf("init tf-apply OIDC validator: %v", err)
		}

		tfOrch := &tfapply.Orchestrator{
			TFBinary:  cfg.TFBinaryPath,
			GitBinary: cfg.TFGitBinaryPath,
			RepoURL:   cfg.TFApplyRepoURL,
			RootDir:   cfg.TFApplyRootDir,
			WorkDir:   cfg.TFApplyWorkDir,
			Env: []string{
				"AWS_ACCESS_KEY_ID=" + cfg.TFAWSAccessKeyID,
				"AWS_SECRET_ACCESS_KEY=" + cfg.TFAWSSecretKey,
				"AWS_REGION=" + cfg.TFAWSRegion,
				"AWS_DEFAULT_REGION=" + cfg.TFAWSRegion,
				"DOCKER_HOST=" + cfg.TFDockerHost,
			},
		}
		if cfg.TFAppID != "" && cfg.TFAppInstallationID != "" && cfg.TFAppPEMPath != "" {
			appSrc := &tfapply.AppTokenSource{
				AppID:          cfg.TFAppID,
				InstallationID: cfg.TFAppInstallationID,
				PEMPath:        cfg.TFAppPEMPath,
			}
			if err := appSrc.Verify(); err != nil {
				log.Fatalf("verify tf-apply App token source: %v", err)
			}
			tfOrch.TokenSource = appSrc
		}

		srvCfg.TFApplyValidator = tfValidator
		srvCfg.TFApplier = tfOrch
		log.Printf("engram-deployer: /tf-apply enabled (repo=%s root=%s)",
			cfg.TFApplyRepository, cfg.TFApplyRootDir)

		// /tf-plan piggybacks on the same Orchestrator (which implements
		// TFPlanner as well as TFApplier). Distinct validator: PR-event
		// tokens carry sub=repo:<repo>:pull_request and a workflow_ref
		// containing tf-plan.yml; ref varies per PR so it's not pinned.
		planSubject := fmt.Sprintf("repo:%s:pull_request", cfg.TFApplyRepository)
		planWorkflowPrefix := fmt.Sprintf("%s/.github/workflows/%s@",
			cfg.TFApplyRepository, cfg.TFPlanWorkflowFile)
		planValidator, err := auth.NewValidator(ctx, auth.OIDCConfig{
			JWKSURL:           cfg.JWKSURL,
			Issuer:            cfg.Issuer,
			Audience:          cfg.TFPlanAudience,
			Repository:        cfg.TFApplyRepository,
			Subject:           planSubject,
			WorkflowRefPrefix: planWorkflowPrefix,
		})
		if err != nil {
			log.Fatalf("init tf-plan OIDC validator: %v", err)
		}
		srvCfg.TFPlanValidator = planValidator
		srvCfg.TFPlanner = tfOrch
		log.Printf("engram-deployer: /tf-plan enabled (sub=%s workflow_ref prefix=%s)",
			planSubject, planWorkflowPrefix)
	} else {
		log.Printf("engram-deployer: /tf-apply + /tf-plan disabled (no DEPLOYER_TF_APPLY_* env)")
	}

	srv := server.New(srvCfg)

	log.Printf("engram-deployer listening on %s", cfg.Addr)
	if err := srv.ListenAndServeTLS(ctx, cfg.Addr, cfg.CertFile, cfg.KeyFile); err != nil {
		log.Fatalf("server: %v", err)
	}
}
