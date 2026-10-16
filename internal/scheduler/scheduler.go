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
	"github.com/gr0gu/cerberus/internal/identity"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/posture"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/storage"
)

// Scheduler manages independent concurrent goroutines for network discovery and vulnerability analysis.
type Scheduler struct {
	cfg              *config.Config
	storage          *storage.Storage
	scanner          *scanner.Scanner
	discoveryService *discovery.Service
	matcher          *identity.Matcher
	postureService   *posture.Service

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
		matcher:           identity.NewMatcher(store, identity.DefaultWeights(), time.Now),
		postureService:    posture.NewService(store, posture.DefaultPolicy),
		immediateVulnCh:   make(chan string, 100),
		manualDiscoveryCh: make(chan chan error, 5),
		manualVulnCh:      make(chan chan error, 5),
	}

	// Wire discovery service to push new devices to immediateVulnCh
	s.discoveryService = discovery.New(cfg, store, scn, s.EnqueueImmediateScan)
	s.storage.SetDiscoveryInterval(cfg.DiscoveryInterval)

	return s
}

// SetPostureService assigns or overrides the posture evaluation service.
func (s *Scheduler) SetPostureService(svc *posture.Service) {
	s.postureService = svc
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

// Start boots the background goroutines:
// 1. Discovery Worker (cron: 30 minutes)
// 2. Periodic Vulnerability Worker (cron: 10 minutes)
// 3. Immediate Reactive Vulnerability Worker (event-driven queue)
// 4. Daily Retention Worker (90-day retention)
// 5. Hourly Posture Snapshot Worker
func (s *Scheduler) Start(ctx context.Context) {
	log.Printf("[Scheduler] Starting background engines (Discovery: %v, Vulnerability: %v)",
		s.cfg.DiscoveryInterval, s.cfg.VulnerabilityInterval)

	s.wg.Add(5)
	go s.runDiscoveryWorker(ctx)
	go s.runPeriodicVulnWorker(ctx)
	go s.runImmediateVulnWorker(ctx)
	go s.runRetentionWorker(ctx)
	go s.runPostureWorker(ctx)
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
				// Allow newly booted endpoints a short window to finish binding ports
				time.Sleep(3 * time.Second)

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
	// Deduplicate target IPs so a single scan never probes the same IP multiple times
	seenTargets := make(map[string]bool, len(targets))
	dedupedTargets := make([]string, 0, len(targets))
	for _, t := range targets {
		if t != "" && !seenTargets[t] {
			seenTargets[t] = true
			dedupedTargets = append(dedupedTargets, t)
		}
	}
	targets = dedupedTargets
	if len(targets) == 0 {
		return nil
	}

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

	isUnprivileged := (s.scanner.Capabilities() != nil && s.scanner.Capabilities().EffectiveMode == "unprivileged") || s.cfg.ForceUnprivileged

	totalVulnsFound := 0
	for _, res := range results {
		var observedPorts []int
		for _, svc := range res.Services {
			if svc.State == "open" || svc.State == "" {
				observedPorts = append(observedPorts, svc.Port)
			}
		}

		// When unprivileged (-Pn), Nmap marks every target IP as "up" even if no host is listening.
		// Skip the host BEFORE calling matcher.Resolve / ApplyDecision if 0 ports are open and no MAC was seen.
		if isUnprivileged && len(observedPorts) == 0 && res.MAC == "" {
			continue
		}

		portProfile, _ := identity.PortProfile(res.Services)
		obs := identity.Observation{
			IP:           res.IP,
			MAC:          res.MAC,
			Hostname:     res.Hostname,
			Ports:        portProfile,
			Fingerprints: res.Fingerprints,
			ObservedAt:   start,
		}
		dec, err := s.matcher.Resolve(ctx, obs)
		if err != nil {
			log.Printf("[%s Scan] Error resolving identity for %s: %v", scanType, res.IP, err)
			continue
		}

		err = s.storage.WithTx(ctx, func(tx *storage.Tx) error {
			dev, err := tx.ApplyDecision(ctx, dec, obs)
			if err != nil {
				return fmt.Errorf("applying decision for %s: %w", res.IP, err)
			}
			if dev == nil {
				return nil
			}

			// Save Services
			for _, svc := range res.Services {
				svc.DeviceID = dev.ID
				if _, err := tx.UpsertService(ctx, &svc); err != nil {
					log.Printf("[%s Scan] Error saving service %d for %s: %v", scanType, svc.Port, res.IP, err)
				}
			}

			// Save Vulnerabilities
			for _, vuln := range res.Vulnerabilities {
				vuln.DeviceID = dev.ID
				if _, _, err := tx.UpsertVulnerability(ctx, &vuln); err != nil {
					log.Printf("[%s Scan] Error saving vuln %s for %s: %v", scanType, vuln.CVEID, res.IP, err)
				} else {
					totalVulnsFound++
				}
			}

			hostStatus := res.Status
			if hostStatus == "" {
				hostStatus = "up"
			}

			// Reconcile host findings if host is up
			if hostStatus == "up" {
				if err := tx.ReconcileHostFindings(ctx, dev.ID, start.UTC(), observedPorts); err != nil {
					log.Printf("[%s Scan] Error reconciling host findings for %s: %v", scanType, res.IP, err)
				}
			}

			// Record point-in-time observation with newly evaluated vulnerability posture
			if scanLog != nil {
				isVuln, vulnsCount, maxSev, _ := tx.GetDeviceSecurityPosture(ctx, dev.ID)
				_ = tx.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
					DeviceID:     dev.ID,
					ScanID:       scanLog.ID,
					Status:       hostStatus,
					IsVulnerable: isVuln,
					VulnsCount:   vulnsCount,
					MaxSeverity:  maxSev,
					RecordedAt:   time.Now().UTC(),
				})
			}
			return nil
		})
		if err != nil {
			log.Printf("[%s Scan] Error persisting host %s: %v", scanType, res.IP, err)
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

	if s.postureService != nil {
		if _, snapErr := s.postureService.Snapshot(ctx); snapErr != nil {
			log.Printf("[%s Scan] Error creating posture snapshot: %v", scanType, snapErr)
		}
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

// -------------------------------------------------------------
// Goroutine 4: Daily Retention Worker (Purge 90d data)
// -------------------------------------------------------------
func (s *Scheduler) runRetentionWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Initial purge upon startup
	recDeleted, scanDeleted, err := s.storage.PurgeOlderThan(ctx, 90*24*time.Hour, 90*24*time.Hour)
	if err != nil {
		log.Printf("[Retention Worker] Error during startup purge: %v", err)
	} else if recDeleted > 0 || scanDeleted > 0 {
		log.Printf("[Retention Worker] Startup purge removed %d records and %d scans", recDeleted, scanDeleted)
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("[Retention Worker] Shutting down.")
			return
		case <-ticker.C:
			recDeleted, scanDeleted, err := s.storage.PurgeOlderThan(ctx, 90*24*time.Hour, 90*24*time.Hour)
			if err != nil {
				log.Printf("[Retention Worker] Error during purge: %v", err)
			} else if recDeleted > 0 || scanDeleted > 0 {
				log.Printf("[Retention Worker] Purged %d records and %d scans older than 90 days", recDeleted, scanDeleted)
			}
		}
	}
}

// -------------------------------------------------------------
// Goroutine 5: Hourly Posture Snapshot Worker
// -------------------------------------------------------------
func (s *Scheduler) runPostureWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Initial snapshot on startup
	if s.postureService != nil {
		if _, err := s.postureService.Snapshot(ctx); err != nil {
			log.Printf("[Posture Worker] Startup snapshot error: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("[Posture Worker] Shutting down.")
			return
		case <-ticker.C:
			if s.postureService != nil {
				if _, err := s.postureService.Snapshot(ctx); err != nil {
					log.Printf("[Posture Worker] Hourly snapshot error: %v", err)
				}
			}
		}
	}
}
