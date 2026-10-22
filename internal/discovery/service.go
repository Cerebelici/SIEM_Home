package discovery

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/identity"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/storage"
)

// OnNewDeviceFunc is a callback invoked whenever a new device is discovered.
type OnNewDeviceFunc func(ip string)

// Service coordinates network host discovery and alerts listeners to new hosts.
type Service struct {
	cfg         *config.Config
	storage     *storage.Storage
	scanner     *scanner.Scanner
	matcher     *identity.Matcher
	onNewDevice OnNewDeviceFunc
}

// New creates a new Discovery Service.
func New(cfg *config.Config, store *storage.Storage, scn *scanner.Scanner, onNew OnNewDeviceFunc) *Service {
	return &Service{
		cfg:         cfg,
		storage:     store,
		scanner:     scn,
		matcher:     identity.NewMatcher(store, identity.DefaultWeights(), time.Now),
		onNewDevice: onNew,
	}
}

// Run executes a network discovery scan, stores live hosts, and immediately
// triggers vulnerability scanning for any newly discovered host.
func (s *Service) Run(ctx context.Context) ([]model.Device, error) {
	start := time.Now().UTC()
	targetSpec := s.cfg.NetworkCIDR
	log.Printf("[Discovery] Starting host discovery on %s", targetSpec)

	scanLog, err := s.storage.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "discovery",
		Status:     "running",
		TargetSpec: targetSpec,
	})
	if err != nil {
		log.Printf("[Discovery] Failed to create scan log: %v", err)
	}

	devices, scanErr := s.scanner.RunDiscoveryScan(ctx, targetSpec)
	duration := time.Since(start).Milliseconds()

	if scanErr != nil {
		log.Printf("[Discovery] Scan error: %v", scanErr)
		if scanLog != nil {
			scanLog.Status = "failed"
			scanLog.ErrorMessage = scanErr.Error()
			scanLog.DurationMs = duration
			_ = s.storage.UpdateScanLog(ctx, scanLog)
		}
		return nil, fmt.Errorf("discovery scan failed: %w", scanErr)
	}

	var newDevicesCount int
	observedIDs := make([]int64, 0, len(devices))

	for i := range devices {
		resolvedHost, resolvedVendor := ResolveHostnameAndVendor(ctx, devices[i].IP, devices[i].Hostname, devices[i].Vendor, devices[i].MAC)
		if resolvedHost != "" {
			devices[i].Hostname = resolvedHost
		}
		if resolvedVendor != "" {
			devices[i].Vendor = resolvedVendor
		}

		obs := identity.Observation{
			IP:           devices[i].IP,
			MAC:          devices[i].MAC,
			Hostname:     devices[i].Hostname,
			Vendor:       devices[i].Vendor,
			Fingerprints: devices[i].Fingerprints,
			ObservedAt:   start,
		}
		dec, err := s.matcher.Resolve(ctx, obs)
		if err != nil {
			log.Printf("[Discovery] Error resolving identity for %s: %v", devices[i].IP, err)
			continue
		}

		savedDev, err := s.storage.ApplyDecision(ctx, dec, obs)
		if err != nil {
			log.Printf("[Discovery] Error applying decision for %s: %v", devices[i].IP, err)
			continue
		}

		observedIDs = append(observedIDs, savedDev.ID)

		// Record point-in-time observation for live device
		if scanLog != nil {
			isVuln, vulnsCount, maxSev, _ := s.storage.GetDeviceSecurityPosture(ctx, savedDev.ID)
			_ = s.storage.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
				DeviceID:     savedDev.ID,
				ScanID:       scanLog.ID,
				Status:       "up",
				IsVulnerable: isVuln,
				VulnsCount:   vulnsCount,
				MaxSeverity:  maxSev,
				RecordedAt:   start,
			})
		}

		if dec.Action == identity.ActionCreateNew {
			newDevicesCount++
			log.Printf("[Discovery] ⚡ NEW DEVICE DETECTED: %s (%s, %s). Triggering immediate vulnerability scan!",
				savedDev.CurrentIP, savedDev.Hostname, savedDev.Vendor)

			if s.onNewDevice != nil {
				// Immediate reactive trigger!
				s.onNewDevice(savedDev.CurrentIP)
			}
		}
	}

	// Mark missing devices as down and record their down observation
	if scanLog != nil {
		if err := s.storage.MarkMissingDevicesDown(ctx, scanLog.ID, observedIDs, start); err != nil {
			log.Printf("[Discovery] Error updating missing devices: %v", err)
		}
	}

	log.Printf("[Discovery] Completed. Discovered %d live hosts (%d new) in %dms",
		len(devices), newDevicesCount, duration)

	if scanLog != nil {
		scanLog.Status = "completed"
		scanLog.HostsFound = len(devices)
		scanLog.DurationMs = duration
		_ = s.storage.UpdateScanLog(ctx, scanLog)
	}

	return devices, nil
}
