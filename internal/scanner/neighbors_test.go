package scanner

import (
	"context"
	"reflect"
	"testing"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
)

// Real `arp -anx` output from macOS right after a TCP ping sweep of 192.168.0.0/24.
const darwinARPTable = `Neighbor                Linklayer Address Expire(O) Expire(I)          Netif Refs Prbs RSSI    LQM     NPM
192.168.0.0             ff:ff:ff:ff:ff:ff (none)    (none)         en0
192.168.0.1             b0:a7:b9:22:8d:2c 1m33s     59s            en0    1 none unknown unknown unknown
192.168.0.2             (incomplete)      (none)    (none)         en0
192.168.0.100           54:bd:79:49:c2:69 1m3s      24s            en0    1 none unknown unknown unknown
192.168.0.101           80:d:3f:4d:e9:68  2m25s     44s            en0    1 none unknown unknown unknown
192.168.0.118           8a:48:f7:c7:6d:5f expired   expired        en0    1 none unknown unknown unknown
192.168.0.255           ff:ff:ff:ff:ff:ff (none)    (none)         en0
224.0.0.251             1:0:5e:0:0:fb     (none)    (none)         en0
`

func TestParseDarwinARPTable_KeepsOnlyRecentlyConfirmedEntries(t *testing.T) {
	got := parseDarwinARPTable(darwinARPTable)
	want := []Neighbor{
		{IP: "192.168.0.1", MAC: "B0:A7:B9:22:8D:2C"},
		{IP: "192.168.0.100", MAC: "54:BD:79:49:C2:69"},
		{IP: "192.168.0.101", MAC: "80:0D:3F:4D:E9:68"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseDarwinARPTable() = %+v, want %+v", got, want)
	}
}

func TestNormalizeARPMAC(t *testing.T) {
	tests := map[string]string{
		"80:d:3f:4d:e9:68":  "80:0D:3F:4D:E9:68",
		"1:0:5e:0:0:fb":     "01:00:5E:00:00:FB",
		"ff:ff:ff:ff:ff:ff": "",
		"(incomplete)":      "",
		"80:d:3f:4d:e9":     "",
		"80:d:3f:4d:e9:zz":  "",
	}
	for in, want := range tests {
		if got := normalizeARPMAC(in); got != want {
			t.Errorf("normalizeARPMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMergeNeighbors(t *testing.T) {
	devices := []model.Device{
		{IP: "192.168.0.1", Status: "up"},
		{IP: "192.168.0.101", MAC: "80:0D:3F:4D:E9:68", Status: "up"},
	}
	neighbors := []Neighbor{
		{IP: "192.168.0.1", MAC: "B0:A7:B9:22:8D:2C"},   // fills the missing MAC
		{IP: "192.168.0.101", MAC: "11:22:33:44:55:66"}, // keeps the MAC nmap reported
		{IP: "192.168.0.118", MAC: "8A:48:F7:C7:6D:5F"}, // added: ignores TCP probes
		{IP: "192.168.0.100", MAC: "54:BD:79:49:C2:69"}, // added, sorted before .118
		{IP: "192.168.0.117", MAC: "AA:AA:AA:AA:AA:AA"}, // excluded own address
		{IP: "192.168.0.255", MAC: "BB:BB:BB:BB:BB:BB"}, // broadcast address
		{IP: "10.0.0.5", MAC: "CC:CC:CC:CC:CC:CC"},      // outside the target
	}

	got := mergeNeighbors(devices, neighbors, "192.168.0.0/24", []string{"192.168.0.117"})
	want := []model.Device{
		{IP: "192.168.0.1", MAC: "B0:A7:B9:22:8D:2C", Status: "up"},
		{IP: "192.168.0.101", MAC: "80:0D:3F:4D:E9:68", Status: "up"},
		{IP: "192.168.0.100", MAC: "54:BD:79:49:C2:69", Status: "up"},
		{IP: "192.168.0.118", MAC: "8A:48:F7:C7:6D:5F", Status: "up"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeNeighbors() = %+v, want %+v", got, want)
	}
}

func TestRunDiscoveryScan_MergesNeighborTable(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><status state="up"/><address addr="192.168.0.1" addrtype="ipv4"/></host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>`
	runner := &recordingRunner{output: []byte(xml)}
	sc := NewWithRunner(&config.Config{NmapPath: "nmap"}, runner)
	sc.SetNeighborSource(func(context.Context) ([]Neighbor, error) {
		return []Neighbor{
			{IP: "192.168.0.1", MAC: "B0:A7:B9:22:8D:2C"},
			{IP: "192.168.0.100", MAC: "54:BD:79:49:C2:69"},
		}, nil
	})

	devices, err := sc.RunDiscoveryScan(context.Background(), "192.168.0.0/24")
	if err != nil {
		t.Fatalf("RunDiscoveryScan() error: %v", err)
	}
	if len(devices) != 2 || devices[0].MAC != "B0:A7:B9:22:8D:2C" || devices[1].IP != "192.168.0.100" {
		t.Errorf("unexpected devices: %+v", devices)
	}
	for _, arg := range runner.args {
		if arg == "--exclude" {
			t.Errorf("no --exclude expected when no address is excluded, got args %v", runner.args)
		}
	}
}

type recordingRunner struct {
	output []byte
	args   []string
}

func (r *recordingRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.args = args
	return r.output, nil
}

func TestRunVulnerabilityScan_FillsMACFromNeighborTable(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><status state="up"/><address addr="192.168.0.101" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="8008"><state state="open"/><service name="http"/></port></ports>
  </host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>`
	sc := NewWithRunner(&config.Config{NmapPath: "nmap"}, &recordingRunner{output: []byte(xml)})
	sc.SetNeighborSource(func(context.Context) ([]Neighbor, error) {
		return []Neighbor{{IP: "192.168.0.101", MAC: "80:0D:3F:4D:E9:68"}}, nil
	})

	results, err := sc.RunVulnerabilityScan(context.Background(), []string{"192.168.0.101"})
	if err != nil {
		t.Fatalf("RunVulnerabilityScan() error: %v", err)
	}
	if len(results) != 1 || results[0].MAC != "80:0D:3F:4D:E9:68" {
		t.Errorf("expected the MAC from the ARP table, got %+v", results)
	}
}
