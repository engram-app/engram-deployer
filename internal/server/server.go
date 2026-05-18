package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/engram-app/engram-deployer/internal/auth"
)

// Config bundles the dependencies a Server needs.
//
// /deploy is always wired. /tf-apply is wired only when both
// TFApplyValidator and TFApplier are non-nil — leaving either nil
// disables the endpoint entirely (404).
type Config struct {
	Validator *auth.Validator
	JTI       *auth.JTISet
	IPAllow   *auth.IPAllowlist
	Deployer  Deployer

	TFApplyValidator *auth.Validator
	TFApplier        TFApplier
}

// Server is the HTTP entrypoint for the deployer daemon.
// All request validation (IP, OIDC, JTI) lives here; deploy logic is
// delegated to a Deployer that the server holds via interface.
type Server struct {
	cfg Config
	mux *http.ServeMux

	mu                sync.RWMutex
	lastResult        *DeployResult
	lastTFApplyResult *TFApplyResult

	// applyMu serializes /deploy and /tf-apply — both mutate Docker
	// state on the same host and must not run concurrently.
	applyMu sync.Mutex
}

// New wires the routes against cfg.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("POST /deploy", s.deploy)
	s.mux.HandleFunc("GET /status", s.status)
	if cfg.TFApplyValidator != nil && cfg.TFApplier != nil {
		s.mux.HandleFunc("POST /tf-apply", s.tfApply)
		s.mux.HandleFunc("GET /tf-apply/status", s.tfApplyStatus)
	}
	return s
}

// Handler returns the configured http.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServeTLS starts the daemon on addr with the given cert/key.
// Blocks until ctx is cancelled, then gracefully shuts down with a 10s
// drain budget for in-flight requests (typical deploy completes in seconds).
func (s *Server) ListenAndServeTLS(ctx context.Context, addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Deploys can run several minutes; ReadTimeout=0 and WriteTimeout=0
		// would let a slowloris hang us. Cap at 15 minutes — well beyond any
		// reasonable deploy, far short of indefinite.
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	listenErr := make(chan error, 1)
	go func() {
		err := srv.ListenAndServeTLS(certFile, keyFile)
		if !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
		}
		close(listenErr)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-listenErr:
		return err
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
