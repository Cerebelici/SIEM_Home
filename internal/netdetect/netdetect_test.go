package netdetect

import (
	"testing"
)

func TestListActiveInterfaces(t *testing.T) {
	ifaces, err := ListActiveInterfaces()
	if err != nil {
		t.Fatalf("unexpected error listing interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Name == "" {
			t.Errorf("expected non-empty interface name")
		}
		if iface.IPv4 == "" {
			t.Errorf("expected non-empty IPv4 for %s", iface.Name)
		}
		if iface.CIDR == "" {
			t.Errorf("expected non-empty CIDR for %s", iface.Name)
		}
		t.Logf("Detected interface: %+v", iface)
	}
}

func TestDetectDefaultNetwork(t *testing.T) {
	def, err := DetectDefaultNetwork()
	if err != nil {
		t.Logf("No default network detected (e.g. offline): %v", err)
		return
	}

	if def.Name == "" || def.IPv4 == "" || def.CIDR == "" {
		t.Errorf("detected default network has empty fields: %+v", def)
	}
	t.Logf("Default network selected: %+v", def)
}

func TestIsIgnoredInterface(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"docker0", true},
		{"br-12345", true},
		{"vethabcdef", true},
		{"utun4", true},
		{"awdl0", true},
		{"en0", false},
		{"eth0", false},
		{"wlan0", false},
		{"Wi-Fi", false},
	}

	for _, tc := range tests {
		got := isIgnoredInterface(tc.name)
		if got != tc.expected {
			t.Errorf("isIgnoredInterface(%q) = %v, expected %v", tc.name, got, tc.expected)
		}
	}
}

