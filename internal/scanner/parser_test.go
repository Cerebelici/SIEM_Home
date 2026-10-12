package scanner_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
)

const sampleDiscoveryXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 172.28.0.0/24" start="1690000000" version="7.94">
  <host starttime="1690000001" endtime="1690000002">
    <status state="up" reason="arp-response"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <address addr="02:42:AC:1C:00:0A" addrtype="mac" vendor="Docker Network"/>
    <hostnames>
      <hostname name="target-nginx" type="user"/>
    </hostnames>
  </host>
  <host starttime="1690000001" endtime="1690000002">
    <status state="up" reason="arp-response"/>
    <address addr="172.28.0.20" addrtype="ipv4"/>
    <address addr="02:42:AC:1C:00:14" addrtype="mac" vendor="Docker Network"/>
    <hostnames>
      <hostname name="target-redis" type="user"/>
    </hostnames>
  </host>
  <host starttime="1690000001" endtime="1690000002">
    <status state="down" reason="no-response"/>
    <address addr="172.28.0.99" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1690000005" summary="done" elapsed="5.0" exit="success"/>
    <hosts up="2" down="1" total="3"/>
  </runstats>
</nmaprun>`

const sampleVulnXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script vulners 172.28.0.10" start="1690000000" version="7.94">
  <host starttime="1690000001" endtime="1690000010">
    <status state="up" reason="syn-ack"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target-nginx" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.21.6" method="probed" conf="10"/>
        <script id="vulners" output="&#xa;  nginx 1.21.6:&#xa;    CVE-2021-23017  7.5  https://vulners.com/cve/CVE-2021-23017&#xa;    CVE-2022-41741  9.8  https://vulners.com/cve/CVE-2022-41741">
          <table key="cpe:/a:igor_sysoev:nginx:1.21.6">
            <table key="CVE-2021-23017">
              <elem key="type">cve</elem>
              <elem key="id">CVE-2021-23017</elem>
              <elem key="cvss">7.5</elem>
              <elem key="is_exploit">false</elem>
            </table>
            <table key="CVE-2022-41741">
              <elem key="type">cve</elem>
              <elem key="id">CVE-2022-41741</elem>
              <elem key="cvss">9.8</elem>
              <elem key="is_exploit">false</elem>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>`

type mockRunner struct {
	output []byte
	err    error
}

func (m *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return m.output, m.err
}

func TestExtractDevices(t *testing.T) {
	run, err := scanner.ParseNmapXML([]byte(sampleDiscoveryXML))
	if err != nil {
		t.Fatalf("unexpected error parsing discovery XML: %v", err)
	}

	devices := scanner.ExtractDevices(run)
	if len(devices) != 2 {
		t.Fatalf("expected 2 active devices, got %d", len(devices))
	}

	dev1 := devices[0]
	if dev1.IP != "172.28.0.10" || dev1.MAC != "02:42:AC:1C:00:0A" || dev1.Hostname != "target-nginx" {
		t.Errorf("unexpected dev1: %+v", dev1)
	}

	dev2 := devices[1]
	if dev2.IP != "172.28.0.20" || dev2.Hostname != "target-redis" {
		t.Errorf("unexpected dev2: %+v", dev2)
	}
}

func TestExtractHostResults_WithVulns(t *testing.T) {
	run, err := scanner.ParseNmapXML([]byte(sampleVulnXML))
	if err != nil {
		t.Fatalf("unexpected error parsing vuln XML: %v", err)
	}

	results := scanner.ExtractHostResults(run)
	if len(results) != 1 {
		t.Fatalf("expected 1 host result, got %d", len(results))
	}

	host := results[0]
	if host.IP != "172.28.0.10" {
		t.Errorf("expected IP 172.28.0.10, got %s", host.IP)
	}

	if len(host.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(host.Services))
	}
	svc := host.Services[0]
	if svc.Port != 80 || svc.ServiceName != "http" || svc.Product != "nginx" || svc.Version != "1.21.6" {
		t.Errorf("unexpected service details: %+v", svc)
	}

	if len(host.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(host.Vulnerabilities))
	}

	// Verify CVE extraction and severity calculation
	cveMap := make(map[string]float64)
	for _, v := range host.Vulnerabilities {
		cveMap[v.CVEID] = v.CVSSScore
	}

	if score, ok := cveMap["CVE-2021-23017"]; !ok || score != 7.5 {
		t.Errorf("expected CVE-2021-23017 with CVSS 7.5, got %v (score %f)", ok, score)
	}
	if score, ok := cveMap["CVE-2022-41741"]; !ok || score != 9.8 {
		t.Errorf("expected CVE-2022-41741 with CVSS 9.8, got %v (score %f)", ok, score)
	}
}

func TestScanner_WithMockRunner(t *testing.T) {
	cfg := &config.Config{
		NmapPath:   "nmap",
		VulnScript: "vulners",
	}

	mock := &mockRunner{output: []byte(sampleDiscoveryXML)}
	sc := scanner.NewWithRunner(cfg, mock)

	devices, err := sc.RunDiscoveryScan(context.Background(), "172.28.0.0/24")
	if err != nil {
		t.Fatalf("run discovery scan error: %v", err)
	}
	if len(devices) != 2 {
		t.Errorf("expected 2 devices, got %d", len(devices))
	}
}

func TestParser_VulnersExploitFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/vulners_exploit.xml")
	if err != nil {
		t.Fatalf("reading vulners_exploit.xml fixture: %v", err)
	}

	run, err := scanner.ParseNmapXML(data)
	if err != nil {
		t.Fatalf("parsing XML: %v", err)
	}

	results := scanner.ExtractHostResults(run)
	if len(results) == 0 {
		t.Fatalf("expected host results, got none")
	}

	var targetVuln *model.Vulnerability
	for _, v := range results[0].Vulnerabilities {
		if v.CVEID == "CVE-2021-23017" {
			targetVuln = &v
			break
		}
	}

	if targetVuln == nil {
		t.Fatalf("expected CVE-2021-23017 to be parsed")
	}

	if !targetVuln.IsExploit {
		t.Errorf("expected IsExploit=true, got false")
	}

	foundEDB := false
	for _, ref := range targetVuln.ExploitRefs {
		if strings.HasPrefix(ref, "EDB-ID:") {
			foundEDB = true
			break
		}
	}
	if !foundEDB {
		t.Errorf("expected ExploitRefs to contain EDB-ID:..., got %v", targetVuln.ExploitRefs)
	}
}

func TestRegexFallback_IgnoresVersion(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 172.28.0.10" start="1690000000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
        <script id="ssh-vuln" output="OpenSSH 7.4 CVE-2018-15473 5.3"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	run, err := scanner.ParseNmapXML([]byte(xmlContent))
	if err != nil {
		t.Fatalf("parsing XML: %v", err)
	}

	results := scanner.ExtractHostResults(run)
	if len(results) == 0 || len(results[0].Vulnerabilities) == 0 {
		t.Fatalf("expected vulnerabilities parsed from script output, got none")
	}

	vuln := results[0].Vulnerabilities[0]
	if vuln.CVEID != "CVE-2018-15473" {
		t.Errorf("expected CVE-2018-15473, got %s", vuln.CVEID)
	}
	if vuln.CVSSScore != 5.3 {
		t.Errorf("expected CVSS score 5.3, got %f", vuln.CVSSScore)
	}
}

