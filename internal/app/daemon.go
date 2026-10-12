package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"sync"

	"github.com/gr0gu/cerberus/internal/api"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

// Daemon manages the unified lifecycle of Cerberus Sentinel workers, storage, and HTTP server.
type Daemon struct {
	cfg       *config.Config
	store     *storage.Storage
	sched     *scheduler.Scheduler
	srv       *api.Server
	caps      *model.Capabilities
	daemonCtx context.Context
	cancel    context.CancelFunc
	stopOnce  sync.Once
	errCh     chan error
	ln        net.Listener
	mu        sync.Mutex
	started   bool
}

// New constructs a new Daemon instance from configuration.
func New(cfg *config.Config) *Daemon {
	return &Daemon{
		cfg:   cfg,
		errCh: make(chan error, 1),
	}
}

// Start boots preflight, storage, scheduler, and the HTTP server.
// It binds the listening port synchronously so port conflicts are caught immediately.
// It executes using an independent background context so caller context cancellation does not terminate workers.
func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.started {
		return nil
	}

	// 1. Run Preflight capability inspection
	caps, err := scanner.Preflight(ctx, d.cfg, &scanner.DefaultCommandRunner{}, exec.LookPath)
	if err != nil {
		log.Printf("[Daemon] Preflight inspection warning: %v. Falling back to unprivileged.", err)
		caps = &model.Capabilities{
			NmapPath:      d.cfg.NmapPath,
			EffectiveMode: "unprivileged",
			Warnings:      []string{err.Error()},
		}
	}
	d.caps = caps

	// 2. Initialize persistent storage
	store, err := storage.New(d.cfg.DBPath)
	if err != nil {
		return fmt.Errorf("initializing storage: %w", err)
	}

	// Optional mock data seeding
	if d.cfg.SeedMockData {
		_ = store.SeedMockData(context.Background())
	}

	// 3. Bind HTTP listener synchronously to surface port conflicts immediately
	addr := fmt.Sprintf("%s:%d", d.cfg.ServerHost, d.cfg.ServerPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = store.Close()
		return fmt.Errorf("binding server address %s: %w", addr, err)
	}
	d.ln = ln

	// 4. Initialize scanner, scheduler, and API server
	scn := scanner.New(d.cfg, caps)
	sched := scheduler.New(d.cfg, store, scn)
	srv := api.NewServer(d.cfg, store, sched, caps)
	sched.SetPostureService(srv.PostureService())

	// 5. Establish independent daemon execution context
	d.daemonCtx, d.cancel = context.WithCancel(context.Background())

	// 6. Start background workers with daemon context
	sched.Start(d.daemonCtx)

	// 7. Serve HTTP requests
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			select {
			case d.errCh <- serveErr:
			default:
			}
		}
	}()

	d.store = store
	d.sched = sched
	d.srv = srv
	d.started = true

	log.Printf("[Daemon] Started Cerberus Sentinel on %s", ln.Addr().String())
	return nil
}

// Stop gracefully stops all background workers, drains the HTTP server, and closes storage.
// Stop is safe for concurrent invocations and is fully idempotent.
func (d *Daemon) Stop(ctx context.Context) error {
	var stopErr error
	d.stopOnce.Do(func() {
		log.Println("[Daemon] Commencing graceful shutdown...")
		if d.cancel != nil {
			d.cancel()
		}

		if d.sched != nil {
			d.sched.Stop()
		}

		if d.srv != nil {
			if err := d.srv.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
				stopErr = err
			}
		}

		if d.store != nil {
			_ = d.store.Close()
		}

		close(d.errCh)
		d.started = false
		log.Println("[Daemon] Shutdown complete.")
	})
	return stopErr
}

// Errors exposes the channel receiving asynchronous fatal daemon errors.
func (d *Daemon) Errors() <-chan error {
	return d.errCh
}

// Status returns a live snapshot of the sentinel status.
func (d *Daemon) Status() model.SystemStatus {
	d.mu.Lock()
	srv := d.srv
	d.mu.Unlock()

	if srv != nil {
		st, err := srv.GetStatus(context.Background())
		if err == nil {
			return st
		}
	}
	return model.SystemStatus{
		Capabilities: d.caps,
	}
}

// ServerAddr returns the network address the daemon is listening on.
func (d *Daemon) ServerAddr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln != nil {
		return d.ln.Addr().String()
	}
	return fmt.Sprintf("%s:%d", d.cfg.ServerHost, d.cfg.ServerPort)
}

// Port returns the listening port number, or 0 if not listening.
func (d *Daemon) Port() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln != nil {
		if tcpAddr, ok := d.ln.Addr().(*net.TCPAddr); ok {
			return tcpAddr.Port
		}
	}
	return d.cfg.ServerPort
}
