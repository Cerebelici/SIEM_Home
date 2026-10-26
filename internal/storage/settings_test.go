package storage

import (
	"context"
	"testing"

	"github.com/gr0gu/cerberus/internal/model"
)

func TestAppSettingsStorage(t *testing.T) {
	ctx := context.Background()
	store, err := New(":memory:")
	if err != nil {
		t.Fatalf("failed to initialize in-memory storage: %v", err)
	}
	defer store.Close()

	defaults := model.AppSettings{
		NetworkMode:          "auto",
		DiscoveryIntervalSec: 300,
		VulnIntervalSec:      1800,
		UnprivilegedMode:     true,
		NmapPath:             "/usr/bin/nmap",
	}

	// 1. Initial get should return defaults
	got, err := store.GetAppSettings(ctx, defaults)
	if err != nil {
		t.Fatalf("failed to get app settings: %v", err)
	}
	if got.NetworkMode != "auto" || got.DiscoveryIntervalSec != 300 {
		t.Errorf("unexpected settings: %+v", got)
	}

	// 2. Save custom settings
	saved := model.AppSettings{
		NetworkMode:          "custom",
		CustomNetworkCIDR:    "10.0.0.0/24",
		EffectiveCIDR:        "10.0.0.0/24",
		EffectiveExcludeIP:   "10.0.0.5",
		ScanPorts:            "1-1000",
		DiscoveryIntervalSec: 120,
		VulnIntervalSec:      600,
		UnprivilegedMode:     false,
		NmapPath:             "/opt/homebrew/bin/nmap",
	}
	if err := store.SaveAppSettings(ctx, saved); err != nil {
		t.Fatalf("failed to save app settings: %v", err)
	}

	// 3. Verify retrieval
	got2, err := store.GetAppSettings(ctx, defaults)
	if err != nil {
		t.Fatalf("failed to get saved app settings: %v", err)
	}
	if got2.NetworkMode != "custom" || got2.CustomNetworkCIDR != "10.0.0.0/24" || got2.DiscoveryIntervalSec != 120 {
		t.Errorf("retrieved settings mismatch: %+v", got2)
	}
}
