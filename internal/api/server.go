package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/ingest"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

// Server encapsulates the HTTP API and its dependencies.
type Server struct {
	cfg          *config.Config
	storage      *storage.Storage
	scheduler    *scheduler.Scheduler
	server       *http.Server
	startTime    time.Time
	capabilities *model.Capabilities
	dispatcher   *ingest.Dispatcher
}

// NewServer configures routes, middleware, and returns a new Server instance.
func NewServer(cfg *config.Config, store *storage.Storage, sched *scheduler.Scheduler, caps ...*model.Capabilities) *Server {
	var c *model.Capabilities
	if len(caps) > 0 {
		c = caps[0]
	}

	dispatcher := ingest.NewDispatcher(store, cfg.IngestShards)
	dispatcher.Start(context.Background())
	ingestHandler := ingest.NewHandler(cfg, store, dispatcher)

	s := &Server{
		cfg:          cfg,
		storage:      store,
		scheduler:    sched,
		startTime:    time.Now().UTC(),
		capabilities: c,
		dispatcher:   dispatcher,
	}

	mux := http.NewServeMux()

	// REST API routes using Go 1.22+ method-matching patterns
	mux.HandleFunc("GET /api/devices", s.handleGetDevices)
	mux.HandleFunc("GET /api/devices/{id}", s.handleGetDeviceByID)
	mux.HandleFunc("GET /api/services", s.handleGetServices)
	mux.HandleFunc("GET /api/vulnerabilities", s.handleGetVulnerabilities)
	mux.HandleFunc("GET /api/scans", s.handleGetScans)
	mux.HandleFunc("GET /api/timeline", s.handleGetTimeline)
	mux.HandleFunc("POST /api/scans/discovery/trigger", s.handleTriggerDiscovery)
	mux.HandleFunc("POST /api/scans/vulnerability/trigger", s.handleTriggerVuln)
	mux.HandleFunc("GET /api/status", s.handleGetStatus)
	mux.HandleFunc("GET /api/export/json", s.handleExportJSON)

	// Agent Telemetry Ingestion API (DEV-01)
	mux.HandleFunc("POST /api/v1/agent/enroll", ingestHandler.HandleEnroll)
	mux.Handle("POST /api/v1/agent/telemetry", ingest.AgentAuthMiddleware(store, http.HandlerFunc(ingestHandler.HandleTelemetry)))
	mux.HandleFunc("GET /api/agents", ingestHandler.HandleGetAgents)
	mux.HandleFunc("GET /api/agents/{id}", ingestHandler.HandleGetAgentByID)
	mux.HandleFunc("DELETE /api/agents/{id}", ingestHandler.HandleDeleteAgent)
	mux.HandleFunc("GET /api/agent-events", ingestHandler.HandleGetAgentEvents)

	// Health check root
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Wrap mux with CORS, Logging, and Recovery middlewares
	handler := recoveryMiddleware(corsMiddleware(loggingMiddleware(mux)))

	addr := fmt.Sprintf("%s:%d", cfg.ServerHost, cfg.ServerPort)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Handler returns the configured http.Handler (useful for unit/integration testing).
func (s *Server) Handler() http.Handler {
	return s.server.Handler
}

// SetCapabilities updates the server's capability profile.
func (s *Server) SetCapabilities(caps *model.Capabilities) {
	s.capabilities = caps
}

// Capabilities returns the server's capability profile.
func (s *Server) Capabilities() *model.Capabilities {
	return s.capabilities
}

// Start runs the HTTP listener (blocking).
func (s *Server) Start() error {
	log.Printf("[HTTP Server] Listening on http://%s", s.server.Addr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server failed: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the HTTP listener.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("[HTTP Server] Draining and shutting down...")
	if s.dispatcher != nil {
		_ = s.dispatcher.Stop(ctx)
	}
	return s.server.Shutdown(ctx)
}

// --- Middlewares ---

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/agent/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Cerberus-Agent-Id")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *statusResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		log.Printf("[API] %s %s -> %d in %v",
			r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[API PANIC] %v", rec)
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Internal server error occurred",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[API] Failed to encode JSON response: %v", err)
	}
}
