// Package api implements the API server for the ROFL registry.
package api

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog/v3"

	"github.com/ptrus/rofl-attestations/config"
	"github.com/ptrus/rofl-attestations/db"
)

// Server is the API server.
type Server struct {
	cfg          *config.Config
	db           *db.DB
	logger       *slog.Logger
	cardTemplate *template.Template
}

// New creates a new API server.
func New(cfg *config.Config, database *db.DB, logger *slog.Logger) *Server {
	// Parse the app card template once at initialization
	cardTemplate := template.Must(template.New("app-card").Parse(appCardTemplate))

	return &Server{
		cfg:          cfg,
		db:           database,
		logger:       logger,
		cardTemplate: cardTemplate,
	}
}

// Run starts the HTTP server.
func (s *Server) Run(ctx context.Context) error {
	r := chi.NewRouter()

	// Setup CORS only if origins are explicitly configured.
	// Empty list means same-origin only (no CORS).
	if len(s.cfg.Server.AllowedOrigins) > 0 {
		s.logger.Info("enabling CORS", "allowed_origins", s.cfg.Server.AllowedOrigins)
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   s.cfg.Server.AllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT"},
			AllowedHeaders:   []string{"Authorization", "Content-Type"},
			AllowCredentials: false,
		}))
	} else {
		s.logger.Info("CORS not configured - same-origin requests only")
	}

	// Setup global middlewares.
	r.Use(
		middleware.RequestID,
		middleware.RealIP,
		httplog.RequestLogger(s.logger, &httplog.Options{}),
		middleware.Recoverer,
		middleware.Timeout(10*time.Second),
	)

	// Routes.
	r.Get("/", s.serveIndex)

	r.Get("/htmx/apps", s.handleGetApps)
	r.Get("/htmx/apps/{id}", s.handleGetApp)

	// Health check.
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Start server.
	srv := &http.Server{
		Addr:              s.cfg.Server.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.logger.Info("starting server", "addr", s.cfg.Server.ListenAddr)

	// Run server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}
}
