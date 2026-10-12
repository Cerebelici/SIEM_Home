package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/gr0gu/cerberus/internal/api"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

const banner = `
   ____           _                         
  / ___|___ _ __ | |__   ___ _ __ _   _ ___ 
 | |   / _ \ '__|| '_ \ / _ \ '__| | | / __|
 | |__|  __/ |   | |_) |  __/ |  | |_| \__ \
  \____\___|_|   |_.__/ \___|_|   \__,_|___/
  Network Sentinel & Vulnerability Auditor
`

func main() {
	fmt.Print(banner)
	log.Println("[Main] Initializing Cerberus Network Sentinel...")

	// 1. Load Configuration
	cfg := config.Load()
	log.Printf("[Main] Config: Subnet=%s, DiscoveryInterval=%v, VulnInterval=%v, Port=%d, DB=%s",
		cfg.NetworkCIDR, cfg.DiscoveryInterval, cfg.VulnerabilityInterval, cfg.ServerPort, cfg.DBPath)

	// 2. Initialize Database Storage
	store, err := storage.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("[Main] Failed to initialize storage: %v", err)
	}
	defer store.Close()
	log.Printf("[Main] SQLite database connected at %s (WAL mode enabled)", cfg.DBPath)

	// Auto-seed mock data if explicitly requested or if database is empty
	totalDevs, _, _, _, _ := store.GetCounts(context.Background())
	if cfg.SeedMockData || totalDevs == 0 {
		log.Println("[Main] Initializing database with mock timeline data...")
		if err := store.SeedMockData(context.Background()); err != nil {
			log.Printf("[Main] Warning: Failed to seed mock data: %v", err)
		}
	}

	// 3. Preflight & Initialize Scanner Engine
	caps, err := scanner.Preflight(context.Background(), cfg, &scanner.DefaultCommandRunner{}, exec.LookPath)
	if err != nil {
		log.Fatalf("[Main] Preflight check failed: %v", err)
	}
	log.Printf("[Main] Capability profile: Nmap %s (%s), VulnScriptOK=%v, RawSocket=%v, Mode=%s",
		caps.NmapVersion, caps.NmapPath, caps.VulnScriptOK, caps.RawSocket, caps.EffectiveMode)
	for _, w := range caps.Warnings {
		log.Printf("[Main] Capability warning: %s", w)
	}

	scn := scanner.New(cfg, caps)

	// 4. Initialize Scheduler and Goroutine Workers
	sched := scheduler.New(cfg, store, scn)

	// 5. Initialize Web Server and REST API
	srv := api.NewServer(cfg, store, sched, caps)

	// Context for background goroutine lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 6. Start Background Schedulers (Discovery + Periodic Vuln + Immediate Reactive Worker)
	sched.Start(ctx)

	// 7. Start HTTP Server in a Goroutine
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("[Main] HTTP server exited unexpectedly: %v", err)
		}
	}()

	// 8. Graceful Shutdown Interception
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	sig := <-stopCh
	log.Printf("[Main] Received signal '%v'. Commencing graceful shutdown...", sig)

	// Stop background workers
	cancel()
	sched.Stop()

	// Drain and stop HTTP server within 10 seconds
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Main] HTTP server shutdown warning: %v", err)
	}

	log.Println("[Main] Cerberus sentinel stopped cleanly.")
}
