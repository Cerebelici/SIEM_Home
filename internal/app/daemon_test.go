package app_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/app"
	"github.com/gr0gu/cerberus/internal/config"
)

// getFreePort asks the kernel for a free local TCP port.
func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to obtain free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestDaemon_StartStopLifecycle(t *testing.T) {
	port := getFreePort(t)
	cfg := &config.Config{
		ServerHost:            "127.0.0.1",
		ServerPort:            port,
		NetworkCIDR:           "10.0.0.0/24",
		DiscoveryInterval:     10 * time.Minute,
		VulnerabilityInterval: 10 * time.Minute,
		DBPath:                ":memory:",
		IngestShards:          1,
	}

	d := app.New(cfg)
	startCtx, cancelStart := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelStart()

	if err := d.Start(startCtx); err != nil {
		t.Fatalf("daemon.Start error: %v", err)
	}

	// Assert GET /health returns 200 OK
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		t.Fatalf("GET /health error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify Status() method returns valid system status
	status := d.Status()
	if status.Capabilities == nil {
		t.Errorf("expected capabilities in status, got nil")
	}

	// Stop within 10s
	stopCtx, cancelStop := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStop()
	if err := d.Stop(stopCtx); err != nil {
		t.Errorf("daemon.Stop error: %v", err)
	}

	// Second Stop must be a no-op and return nil
	if err := d.Stop(stopCtx); err != nil {
		t.Errorf("second daemon.Stop should be no-op, got error: %v", err)
	}
}

func TestDaemon_PortConflict(t *testing.T) {
	port := getFreePort(t)

	// Pre-bind port
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to bind port: %v", err)
	}
	defer ln.Close()

	cfg := &config.Config{
		ServerHost:            "127.0.0.1",
		ServerPort:            port,
		NetworkCIDR:           "10.0.0.0/24",
		DiscoveryInterval:     10 * time.Minute,
		VulnerabilityInterval: 10 * time.Minute,
		DBPath:                ":memory:",
		IngestShards:          1,
	}

	d := app.New(cfg)
	err = d.Start(context.Background())
	if err == nil {
		_ = d.Stop(context.Background())
		t.Fatalf("expected error binding already-bound port, got nil")
	}
}

func TestDaemon_UsesOwnContext(t *testing.T) {
	port := getFreePort(t)
	cfg := &config.Config{
		ServerHost:            "127.0.0.1",
		ServerPort:            port,
		NetworkCIDR:           "10.0.0.0/24",
		DiscoveryInterval:     10 * time.Minute,
		VulnerabilityInterval: 10 * time.Minute,
		DBPath:                ":memory:",
		IngestShards:          1,
	}

	d := app.New(cfg)
	startCtx, cancelStart := context.WithCancel(context.Background())

	if err := d.Start(startCtx); err != nil {
		t.Fatalf("daemon.Start error: %v", err)
	}

	// Immediately cancel the context passed into Start
	cancelStart()

	// Wait briefly to allow any premature context propagation to fail
	time.Sleep(100 * time.Millisecond)

	// Server should still be healthy and running
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		t.Fatalf("GET /health failed after startCtx cancelled: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK after startCtx cancelled, got %d", resp.StatusCode)
	}

	// Only explicit Stop halts daemon
	stopCtx, cancelStop := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelStop()
	if err := d.Stop(stopCtx); err != nil {
		t.Fatalf("daemon.Stop error: %v", err)
	}
}
