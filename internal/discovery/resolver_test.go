package discovery

import (
	"context"
	"net"
	"testing"
)

func TestInferVendorFromHostname(t *testing.T) {
	tests := []struct {
		hostname string
		expected string
	}{
		{"Alex-iPhone", "Apple, Inc."},
		{"iphone-14-pro.local", "Apple, Inc."},
		{"Maria-iPad.local.", "Apple, Inc."},
		{"MacBook-Pro-de-John", "Apple, Inc."},
		{"Galaxy-S21-Ultra", "Samsung Electronics"},
		{"sm-g998b", "Samsung Electronics"},
		{"Pixel-7a", "Google LLC"},
		{"chromecast-livingroom", "Google LLC"},
		{"Redmi-Note-10", "Xiaomi Communications"},
		{"HUAWEI-P30", "Huawei Device Co."},
		{"OnePlus-9-Pro", "OnePlus Electronics"},
		{"PlayStation-5", "Sony Interactive Entertainment"},
		{"Nintendo-Switch", "Nintendo Co., Ltd."},
		{"Amazon-FireTV", "Amazon Technologies"},
		{"MikroTik-Router", "MikroTik"},
		{"unifi-ap-ac-pro", "Ubiquiti Networks"},
		{"Archer-AX50", "TP-Link Technologies"},
		{"esp32-sensor-01", "Espressif Systems"},
		{"unknown-desktop", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := InferVendorFromHostname(tt.hostname)
		if got != tt.expected {
			t.Errorf("InferVendorFromHostname(%q) = %q, want %q", tt.hostname, got, tt.expected)
		}
	}
}

func TestLookupOUIPrefix(t *testing.T) {
	tests := []struct {
		mac      string
		expected string
	}{
		{"00:03:93:11:22:33", "Apple, Inc."},
		{"08-00-27-AA-BB-CC", "Oracle VirtualBox"},
		{"b8:27:eb:01:02:03", "Raspberry Pi Foundation"},
		{"48:3F:DA:11:22:33", "MikroTik"},
		{"FF:FF:FF:00:00:00", ""},
		{"short", ""},
	}

	for _, tt := range tests {
		got := LookupOUIPrefix(tt.mac)
		if got != tt.expected {
			t.Errorf("LookupOUIPrefix(%q) = %q, want %q", tt.mac, got, tt.expected)
		}
	}
}

func TestBuildAndParseMDNSPTRQuery(t *testing.T) {
	ip := net.ParseIP("192.168.0.102").To4()
	query, err := buildMDNSPTRQuery(ip)
	if err != nil {
		t.Fatalf("buildMDNSPTRQuery failed: %v", err)
	}
	if len(query) < 20 {
		t.Fatalf("query too short: %d", len(query))
	}
}

func TestResolveHostnameAndVendorInference(t *testing.T) {
	ctx := context.Background()

	// Case 1: Hostname has iPhone, MAC is randomized (locally administered: 02:xx)
	host, vendor := ResolveHostnameAndVendor(ctx, "192.168.0.150", "iPhone-de-User", "", "02:00:00:00:00:01")
	if host != "iPhone-de-User" {
		t.Errorf("expected host iPhone-de-User, got %s", host)
	}
	if vendor != "Apple, Inc." {
		t.Errorf("expected vendor Apple, Inc., got %s", vendor)
	}

	// Case 2: OUI known and vendor already supplied
	host2, vendor2 := ResolveHostnameAndVendor(ctx, "192.168.0.1", "router", "MikroTik", "48:3F:DA:11:22:33")
	if host2 != "router" {
		t.Errorf("expected host router, got %s", host2)
	}
	if vendor2 != "MikroTik" {
		t.Errorf("expected vendor MikroTik, got %s", vendor2)
	}
}
