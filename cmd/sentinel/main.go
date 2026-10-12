package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gr0gu/cerberus/internal/app"
	"github.com/gr0gu/cerberus/internal/config"
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

	cfg := config.Load()
	log.Printf("[Main] Config: Subnet=%s, DiscoveryInterval=%v, VulnInterval=%v, Port=%d, DB=%s",
		cfg.NetworkCIDR, cfg.DiscoveryInterval, cfg.VulnerabilityInterval, cfg.ServerPort, cfg.DBPath)

	d := app.New(cfg)
	if err := d.Start(context.Background()); err != nil {
		log.Fatalf("[Main] Failed to start Cerberus daemon: %v", err)
	}

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stopCh:
		log.Printf("[Main] Received signal '%v'. Commencing graceful shutdown...", sig)
	case err := <-d.Errors():
		log.Printf("[Main] Fatal daemon runtime error: %v. Commencing shutdown...", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := d.Stop(shutdownCtx); err != nil {
		log.Printf("[Main] Shutdown error: %v", err)
	}

	log.Println("[Main] Cerberus sentinel stopped cleanly.")
}
