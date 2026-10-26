package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadVendorDatabase_LongestPrefixWins(t *testing.T) {
	dir := t.TempDir()
	content := "# comment line\n" +
		"B0A7B9 TP-Link Systems\n" +
		"70B3D5 IEEE Registration Authority\n" +
		"70B3D5123 Small Vendor (MA-S)\n" +
		"broken-line\n"
	if err := os.WriteFile(filepath.Join(dir, "nmap-mac-prefixes"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NMAPDIR", dir)
	t.Cleanup(func() {
		vendorDBMu.Lock()
		vendorDB = nil
		vendorDBMu.Unlock()
	})

	n, err := LoadVendorDatabase("nmap")
	if err != nil || n != 3 {
		t.Fatalf("LoadVendorDatabase() = %d, %v; want 3 prefixes", n, err)
	}

	tests := map[string]string{
		"b0:a7:b9:22:8d:2c": "TP-Link Systems",
		"70:B3:D5:12:34:56": "Small Vendor (MA-S)",
		"70:B3:D5:99:00:00": "IEEE Registration Authority",
		"00:0C:29:00:00:01": "VMware, Inc.", // built-in list still answers
		"12:34:56:00:00:00": "",
	}
	for mac, want := range tests {
		if got := LookupOUIPrefix(mac); got != want {
			t.Errorf("LookupOUIPrefix(%q) = %q, want %q", mac, got, want)
		}
	}
}

func TestUsableHostname(t *testing.T) {
	tests := map[string]string{
		"localhost.local.":  "",
		"LOCALHOST":         "",
		"192.168.0.10":      "",
		"-":                 "",
		"Alex-iPhone.local": "Alex-iPhone",
		"router.lan.":       "router.lan",
	}
	for in, want := range tests {
		if got := usableHostname(in, "192.168.0.10"); got != want {
			t.Errorf("usableHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
