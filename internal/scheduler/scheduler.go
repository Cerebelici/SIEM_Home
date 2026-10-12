package scheduler

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/discovery"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/storage"
)

// Scheduler manages independent concurrent goroutines for network discovery and vulnerability analysis.
type Scheduler struct {
	cfg              *config.Config
	storage          *storage.Storage
	scanner          *scanner.Scanner
	discoveryService *discovery.Service

	// Concurrency and scheduling
	wg              sync.WaitGroup
	immediateVulnCh chan string
	activeTargets   sync.Map // IP -> bool

	discoveryRunning atomic.Bool
	vulnRunning      atomic.Bool

	discoveryNextRun time.Time
	vulnNextRun      time.Time
	mu               sync.RWMutex

	manualDiscoveryCh chan chan error
	manualVulnCh      chan chan error
}

// New creates a new Scheduler.
func New(cfg *config.Config, store *storage.Storage, scn *scanner.Scanner) *Scheduler {
	s := &Scheduler{
		cfg:               cfg,
		storage:           store,
		scanner:           scn,
		immediateVulnCh:   make(chan string, 100),
		manualDiscoveryCh: make(chan chan error, 5),
		manualVulnCh:      make(chan chan error, 5),
	}

	// Wire discovery service to push new devices to immediateVulnCh
	s.discoveryService = discovery.New(cfg, store, scn, s.EnqueueImmediateScan)

	return s
}

// EnqueueImmediateScan queues a target IP for an immediate on-demand vulnerability scan.
func (s *Scheduler) EnqueueImmediateScan(ip string) {
	select {
	case s.immediateVulnCh <- ip:
		log.Printf("[Scheduler] Enqueued immediate vuln scan for %s", ip)
	default:
		log.Printf("[Scheduler] Immediate scan queue full, dropping %s", ip)
	}
}

// Start boots the three background goroutines:
// 1. Discovery Worker (cron: 30 minutes)
// 2. Periodic Vulnerability Worker (cron: 10 minutes)
// 3. Immediate Reactive Vulnerability Worker (event-driven queue)
func (s *Scheduler) Start(ctx context.Context) {
	log.Printf("[Scheduler] Starting background engines (Discovery: %v, Vulnerability: %v)",
		s.cfg.DiscoveryInterval, s.cfg.VulnerabilityInterval)

	s.wg.Add(3)
	go s.runDiscoveryWorker(ctx)
	go s.runPeriodicVulnWorker(ctx)
	go s.runImmediateVulnWorker(ctx)
}

// Stop waits for all background goroutines to cleanly finish.
func (s *Scheduler) Stop() {
	s.wg.Wait()
	log.Println("[Scheduler] All workers safely stopped.")
}

// -------------------------------------------------------------
// Goroutine 1: Network Discovery (Every 30 Minutes + Manual)
// -------------------------------------------------------------
func (s *Scheduler) runDiscoveryWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.DiscoveryInterval)
	defer ticker.Stop()

	// Perform initial discovery scan immediately on startup
	s.setNextDiscoveryRun(time.Now().Add(s.cfg.DiscoveryInterval))
	s.executeDiscovery(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Discovery Worker] Shutting down.")
			return

		case <-ticker.C:
			s.setNextDiscoveryRun(time.Now().Add(s.cfg.DiscoveryInterval))
			s.executeDiscovery(ctx)

		case respCh := <-s.manualDiscoveryCh:
			err := s.executeDiscovery(ctx)
			respCh <- err
		}
	}
}

func (s *Scheduler) executeDiscovery(ctx context.Context) error {
	if !s.discoveryRunning.CompareAndSwap(false, true) {
		log.Println("[Discovery Worker] Scan already in progress, skipping.")
		return fmt.Errorf("discovery scan already in progress")
	}
	defer s.discoveryRunning.Store(false)

	_, err := s.discoveryService.Run(ctx)
	return err
}

// -------------------------------------------------------------
// Goroutine 2: Periodic Vulnerability Audit (Every 10 Minutes + Manual)
// -------------------------------------------------------------
func (s *Scheduler) runPeriodicVulnWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.VulnerabilityInterval)
	defer ticker.Stop()

	s.setNextVulnRun(time.Now().Add(s.cfg.VulnerabilityInterval))

	for {
		select {
		case <-ctx.Done():
			log.Println("[Vuln Worker] Shutting down periodic scanner.")
			return

		case <-ticker.C:
			s.setNextVulnRun(time.Now().Add(s.cfg.VulnerabilityInterval))
			s.executePeriodicVulnScan(ctx)

		case respCh := <-s.manualVulnCh:
			err := s.executePeriodicVulnScan(ctx)
			respCh <- err
		}
	}
}

func (s *Scheduler) executePeriodicVulnScan(ctx context.Context) error {
	if !s.vulnRunning.CompareAndSwap(false, true) {
		log.Println("[Vuln Worker] Periodic vuln scan already running, skipping.")
		return fmt.Errorf("vulnerability scan already running")
	}
	defer s.vulnRunning.Store(false)

	targets, err := s.storage.GetActiveDeviceIPs(ctx)
	if err != nil {
		log.Printf("[Vuln Worker] Failed to get active targets: %v", err)
		return err
	}

	if len(targets) == 0 {
		log.Println("[Vuln Worker] No active devices found in database to audit.")
		return nil
	}

	log.Printf("[Vuln Worker] Starting periodic vulnerability audit on %d active devices: %v",
		len(targets), targets)

	scanCtx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
	defer cancel()

	return s.scanTargets(scanCtx, targets, "vulnerability")
}

// -------------------------------------------------------------
// Goroutine 3: Immediate Reactive Vulnerability Worker
// -------------------------------------------------------------
func (s *Scheduler) runImmediateVulnWorker(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Immediate Vuln Worker] Shutting down.")
			return

		case ip := <-s.immediateVulnCh:
			// Ensure deduplication so we don't scan the target if already active
			if _, loaded := s.activeTargets.LoadOrStore(ip, true); loaded {
				log.Printf("[Immediate Vuln Worker] Target %s already being scanned, skipping duplicate.", ip)
				continue
			}

			log.Printf("[Immediate Vuln Worker] 🚀 Launching immediate scan on newly discovered host %s", ip)
			go func(targetIP string) {
				defer s.activeTargets.Delete(targetIP)
				// Create an execution context bounded by ScanTimeout
				scanCtx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
				defer cancel()

				if err := s.scanTargets(scanCtx, []string{targetIP}, "immediate"); err != nil {
					log.Printf("[Immediate Vuln Worker] Scan error on %s: %v", targetIP, err)
				}
			}(ip)
		}
	}
}

// -------------------------------------------------------------
// Target Scanner Execution & DB Persistence
// -------------------------------------------------------------
func (s *Scheduler) scanTargets(ctx context.Context, targets []string, scanType string) error {
	start := time.Now()
	targetSpec := fmt.Sprintf("%v", targets)

	scanLog, err := s.storage.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   scanType,
		Status:     "running",
		TargetSpec: targetSpec,
	})
	if err != nil {
		log.Printf("[%s Scan] Failed to create scan log: %v", scanType, err)
	}

	results, scanErr := s.scanner.RunVulnerabilityScan(ctx, targets)
	duration := time.Since(start).Milliseconds()

	if scanErr != nil {
		log.Printf("[%s Scan] Scan error: %v", scanType, scanErr)
		if scanLog != nil {
			scanLog.Status = "failed"
			scanLog.ErrorMessage = scanErr.Error()
			scanLog.DurationMs = duration
			_ = s.storage.UpdateScanLog(ctx, scanLog)
		}
		return scanErr
	}

	totalVulnsFound := 0
	for _, res := range results {
		dev, err := s.storage.GetDeviceByIP(ctx, res.IP)
		if err != nil || dev == nil {
			// If device wasn't in DB yet, upsert basic info
			dev, _, _ = s.storage.UpsertDevice(ctx, &model.Device{
				IP:       res.IP,
				MAC:      res.MAC,
				Hostname: res.Hostname,
				Vendor:   res.Vendor,
				Status:   "up",
			})
		}

		if dev == nil {
			continue
		}

		// Save Services
		for _, svc := range res.Services {
			svc.DeviceID = dev.ID
			_, err := s.storage.UpsertService(ctx, &svc)
			if err != nil {
				log.Printf("[%s Scan] Error saving service %d for %s: %v", scanType, svc.Port, res.IP, err)
			}
		}

		// Save Vulnerabilities
		for _, vuln := range res.Vulnerabilities {
			vuln.DeviceID = dev.ID
			_, _, err := s.storage.UpsertVulnerability(ctx, &vuln)
			if err != nil {
				log.Printf("[%s Scan] Error saving vuln %s for %s: %v", scanType, vuln.CVEID, res.IP, err)
			} else {
				totalVulnsFound++
			}
		}

		// Record point-in-time observation with newly evaluated vulnerability posture
		if scanLog != nil {
			isVuln, vulnsCount, maxSev, _ := s.storage.GetDeviceSecurityPosture(ctx, dev.ID)
			_ = s.storage.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
				DeviceID:     dev.ID,
				ScanID:       scanLog.ID,
				Status:       "up",
				IsVulnerable: isVuln,
				VulnsCount:   vulnsCount,
				MaxSeverity:  maxSev,
				RecordedAt:   time.Now().UTC(),
			})
		}
	}

	log.Printf("[%s Scan] Finished for %d hosts. Found %d vulnerabilities in %dms",
		scanType, len(results), totalVulnsFound, duration)

	if scanLog != nil {
		scanLog.Status = "completed"
		scanLog.HostsFound = len(results)
		scanLog.VulnsFound = totalVulnsFound
		scanLog.DurationMs = duration
		_ = s.storage.UpdateScanLog(ctx, scanLog)
	}

	return nil
}

// -------------------------------------------------------------
// Control & Status Methods
// -------------------------------------------------------------

// TriggerDiscovery requests an on-demand discovery scan.
func (s *Scheduler) TriggerDiscovery(ctx context.Context) error {
	respCh := make(chan error, 1)
	select {
	case s.manualDiscoveryCh <- respCh:
		select {
		case err := <-respCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("manual discovery request queue busy")
	}
}

// TriggerVulnerabilityScan requests an on-demand vulnerability scan across all active devices.
func (s *Scheduler) TriggerVulnerabilityScan(ctx context.Context) error {
	respCh := make(chan error, 1)
	select {
	case s.manualVulnCh <- respCh:
		select {
		case err := <-respCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("manual vulnerability request queue busy")
	}
}

func (s *Scheduler) setNextDiscoveryRun(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discoveryNextRun = t
}

func (s *Scheduler) setNextVulnRun(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulnNextRun = t
}

// GetNextRuns returns next scheduled execution times and active flags.
func (s *Scheduler) GetNextRuns() (discTime, vulnTime *time.Time, discRunning, vulnRunning bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var dt, vt *time.Time
	if !s.discoveryNextRun.IsZero() {
		copyDt := s.discoveryNextRun
		dt = &copyDt
	}
	if !s.vulnNextRun.IsZero() {
		copyVt := s.vulnNextRun
		vt = &copyVt
	}

	return dt, vt, s.discoveryRunning.Load(), s.vulnRunning.Load()
}
