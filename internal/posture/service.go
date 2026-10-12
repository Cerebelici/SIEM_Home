package posture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// Store defines persistence operations required by the posture service.
type Store interface {
	GetActiveDevicesForPosture(ctx context.Context, activeWindow time.Duration) ([]model.Device, error)
	GetOpenVulnerabilitiesForDevices(ctx context.Context, deviceIDs []int64) (map[int64][]model.Vulnerability, error)
	GetManagedIncidentCounts(ctx context.Context, window time.Duration) (map[string]int, error)
	SavePostureSnapshot(ctx context.Context, snap *model.PostureSnapshot) error
	GetLatestPostureSnapshot(ctx context.Context) (*model.PostureSnapshot, error)
	GetPostureHistory(ctx context.Context, from, to time.Time) ([]model.PostureSnapshot, error)
}

// Service manages live calculation, caching, and snapshotting of fleet posture.
type Service struct {
	store        Store
	policy       Policy
	mu           sync.Mutex
	cachedReport *model.PostureReport
	cachedAt     time.Time
	cacheTTL     time.Duration
}

// NewService creates a new posture service with 30s cache TTL.
func NewService(store Store, policy Policy) *Service {
	return &Service{
		store:    store,
		policy:   policy,
		cacheTTL: 30 * time.Second,
	}
}

// Compute returns the current posture report, using the 30s cache when available.
func (s *Service) Compute(ctx context.Context) (*model.PostureReport, error) {
	s.mu.Lock()
	if s.cachedReport != nil && time.Since(s.cachedAt) < s.cacheTTL {
		report := *s.cachedReport
		s.mu.Unlock()
		return &report, nil
	}
	s.mu.Unlock()

	return s.computeFresh(ctx)
}

// computeFresh performs an un-cached live calculation and updates the cache.
func (s *Service) computeFresh(ctx context.Context) (*model.PostureReport, error) {
	now := time.Now().UTC()
	devices, err := s.store.GetActiveDevicesForPosture(ctx, s.policy.ActiveWindow)
	if err != nil {
		return nil, fmt.Errorf("fetching active devices: %w", err)
	}

	if len(devices) == 0 {
		report := &model.PostureReport{
			ComputedAt:    now,
			PolicyVersion: s.policy.Version,
			FleetScore:    nil,
			PostureStatus: "no_assets",
			ActiveDevices: 0,
			DeviceScores:  []model.DevicePostureSummary{},
		}
		s.mu.Lock()
		s.cachedReport = report
		s.cachedAt = now
		s.mu.Unlock()
		return report, nil
	}

	deviceIDs := make([]int64, len(devices))
	for i, d := range devices {
		deviceIDs[i] = d.ID
	}

	vulnMap, err := s.store.GetOpenVulnerabilitiesForDevices(ctx, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("fetching open vulnerabilities: %w", err)
	}

	incidentCounts, err := s.store.GetManagedIncidentCounts(ctx, s.policy.ActiveWindow)
	if err != nil {
		return nil, fmt.Errorf("fetching incident counts: %w", err)
	}

	penalty := IncidentPenalty(incidentCounts, s.policy)

	var risks []float64
	var maxRisk float64
	var sumRisk float64
	deviceSummaries := make([]model.DevicePostureSummary, len(devices))

	for i, d := range devices {
		vulns := vulnMap[d.ID]
		scores := DeduplicateDeviceCVEs(vulns, s.policy)
		r := HostRisk(scores, s.policy)
		sc := HostScore(r)

		var maxCVE float64
		for _, sVal := range scores {
			if sVal > maxCVE {
				maxCVE = sVal
			}
		}

		risks = append(risks, r)
		if r > maxRisk {
			maxRisk = r
		}
		sumRisk += r

		deviceSummaries[i] = model.DevicePostureSummary{
			DeviceID:  d.ID,
			CurrentIP: d.CurrentIP,
			Hostname:  d.Hostname,
			Managed:   d.Managed,
			Risk:      Round1(r),
			Score:     Round1(sc),
			OpenVulns: len(scores),
			MaxCVE:    Round1(maxCVE),
		}
	}

	meanRisk := sumRisk / float64(len(devices))
	fScore, reason := FleetScore(risks, penalty, s.policy)

	report := &model.PostureReport{
		ComputedAt:    now,
		PolicyVersion: s.policy.Version,
		FleetScore:    fScore,
		PostureStatus: reason,
		ActiveDevices: len(devices),
		MeanRisk:      Round1(meanRisk),
		MaxRisk:       Round1(maxRisk),
		PenaltyTotal:  Round1(penalty),
		DeviceScores:  deviceSummaries,
	}

	s.mu.Lock()
	s.cachedReport = report
	s.cachedAt = now
	s.mu.Unlock()

	return report, nil
}

// Snapshot computes a fresh posture evaluation and stores it in posture_snapshots.
func (s *Service) Snapshot(ctx context.Context) (*model.PostureSnapshot, error) {
	report, err := s.computeFresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("computing posture snapshot: %w", err)
	}

	snap := &model.PostureSnapshot{
		ComputedAt:    report.ComputedAt,
		PolicyVersion: report.PolicyVersion,
		FleetScore:    report.FleetScore,
		ActiveDevices: report.ActiveDevices,
		Details:       report,
	}

	if err := s.store.SavePostureSnapshot(ctx, snap); err != nil {
		return nil, fmt.Errorf("persisting posture snapshot: %w", err)
	}

	return snap, nil
}

// GetHistory queries historical snapshots between [from, to].
func (s *Service) GetHistory(ctx context.Context, from, to time.Time) ([]model.PostureSnapshot, error) {
	return s.store.GetPostureHistory(ctx, from, to)
}

// InvalidateCache clears the 30-second live calculation cache.
func (s *Service) InvalidateCache() {
	s.mu.Lock()
	s.cachedReport = nil
	s.mu.Unlock()
}
