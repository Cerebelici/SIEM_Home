package scanner

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

var (
	anchoredCVERegex   = regexp.MustCompile(`(CVE-\d{4}-\d{4,7})(?:\s+(10(?:\.0)?|\d\.\d)\b)?`)
	sshSHA256TextRegex = regexp.MustCompile(`(?i)\bSHA256:([A-Za-z0-9+/=_-]{16,})`)
	sslSHA256TextRegex = regexp.MustCompile(`(?i)SHA-?256:\s*([0-9a-fA-F:\s]{32,})`)
	uuidTextRegex      = regexp.MustCompile(`(?i)\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

// ParseNmapXML unmarshals raw XML bytes into NmapRun.
func ParseNmapXML(data []byte) (*NmapRun, error) {
	var run NmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap xml: %w", err)
	}
	return &run, nil
}

// ExtractDevices parses active hosts from an Nmap discovery scan.
func ExtractDevices(run *NmapRun) []model.Device {
	var devices []model.Device

	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		var ip, mac, vendor, hostname string

		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if ip == "" {
					ip = addr.Addr
				}
			case "mac":
				mac = addr.Addr
				if addr.Vendor != "" {
					vendor = addr.Vendor
				}
			}
		}

		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		if ip == "" {
			continue
		}

		fps := extractFingerprintsFromScripts(host.HostScripts)

		devices = append(devices, model.Device{
			IP:           ip,
			MAC:          mac,
			Hostname:     hostname,
			Vendor:       vendor,
			Fingerprints: fps,
			Status:       "up",
		})
	}

	return devices
}

// ExtractHostResults parses ports, services, cryptographic fingerprints, and vulnerabilities for all hosts.
func ExtractHostResults(run *NmapRun) []model.ScanHostResult {
	var results []model.ScanHostResult

	for _, host := range run.Hosts {
		var ip, mac, vendor, hostname string

		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if ip == "" {
					ip = addr.Addr
				}
			case "mac":
				mac = addr.Addr
				if addr.Vendor != "" {
					vendor = addr.Vendor
				}
			}
		}

		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		if ip == "" {
			continue
		}

		var services []model.Service
		var vulns []model.Vulnerability
		fpSet := make(map[string]bool)

		for _, fp := range extractFingerprintsFromScripts(host.HostScripts) {
			fpSet[fp] = true
		}

		for _, p := range host.Ports {
			svcState := p.State.State
			if svcState == "" {
				svcState = "open"
			}

			svc := model.Service{
				DeviceIP:    ip,
				Port:        p.PortID,
				Protocol:    p.Protocol,
				ServiceName: p.Service.Name,
				Product:     p.Service.Product,
				Version:     p.Service.Version,
				State:       svcState,
			}
			services = append(services, svc)

			// Parse vulnerabilities from scripts
			extractedVulns := extractVulnerabilitiesFromScripts(ip, p.PortID, p.Scripts)
			vulns = append(vulns, extractedVulns...)

			// Parse Tier 1 cryptographic and hardware fingerprints from scripts
			for _, fp := range extractFingerprintsFromScripts(p.Scripts) {
				fpSet[fp] = true
			}
		}

		var fingerprints []string
		for fp := range fpSet {
			fingerprints = append(fingerprints, fp)
		}
		sort.Strings(fingerprints)

		results = append(results, model.ScanHostResult{
			IP:              ip,
			MAC:             mac,
			Vendor:          vendor,
			Hostname:        hostname,
			Status:          host.Status.State,
			Fingerprints:    fingerprints,
			Services:        services,
			Vulnerabilities: vulns,
		})
	}

	return results
}

func extractFingerprintsFromScripts(scripts []NmapScript) []string {
	if len(scripts) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	addFP := func(prefix, val string) {
		val = strings.ToLower(strings.TrimSpace(val))
		val = strings.ReplaceAll(val, " ", "")
		if val == "" {
			return
		}
		token := fmt.Sprintf("%s:%s", prefix, val)
		seen[token] = true
	}

	for _, script := range scripts {
		id := strings.ToLower(strings.TrimSpace(script.ID))
		switch id {
		case "ssh-hostkey":
			for _, tbl := range script.Tables {
				var fpVal string
				for _, elem := range tbl.Elems {
					if strings.EqualFold(elem.Key, "fingerprint") && elem.Value != "" {
						fpVal = elem.Value
					}
				}
				if fpVal != "" {
					addFP("ssh-hostkey", fpVal)
				}
			}
			for _, elem := range script.Elems {
				if strings.EqualFold(elem.Key, "fingerprint") && elem.Value != "" {
					addFP("ssh-hostkey", elem.Value)
				}
			}
			for _, m := range sshSHA256TextRegex.FindAllStringSubmatch(script.Output, -1) {
				if len(m) > 1 {
					addFP("ssh-hostkey", m[1])
				}
			}

		case "ssl-cert":
			for _, elem := range script.Elems {
				if strings.EqualFold(elem.Key, "sha256") || strings.EqualFold(elem.Key, "sha1") {
					addFP("ssl-cert", elem.Value)
				}
			}
			for _, tbl := range script.Tables {
				for _, elem := range tbl.Elems {
					if strings.EqualFold(elem.Key, "sha256") || strings.EqualFold(elem.Key, "sha1") {
						addFP("ssl-cert", elem.Value)
					}
				}
			}
			for _, m := range sslSHA256TextRegex.FindAllStringSubmatch(script.Output, -1) {
				if len(m) > 1 {
					addFP("ssl-cert", strings.ReplaceAll(m[1], ":", ""))
				}
			}

		case "smb2-capabilities", "smb-os-discovery", "upnp-info", "nbstat":
			for _, elem := range script.Elems {
				if strings.EqualFold(elem.Key, "guid") || strings.EqualFold(elem.Key, "uuid") || strings.EqualFold(elem.Key, "mac") {
					addFP(id, elem.Value)
				}
			}
			for _, m := range uuidTextRegex.FindAllStringSubmatch(script.Output, -1) {
				if len(m) > 1 {
					addFP(id, m[1])
				}
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for fp := range seen {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}

func extractVulnerabilitiesFromScripts(ip string, port int, scripts []NmapScript) []model.Vulnerability {
	var vulns []model.Vulnerability
	seenCVEs := make(map[string]bool)
	now := time.Now().UTC()

	for _, script := range scripts {
		// 1. Structured table parsing (vulners.nse format)
		structuredVulns := parseStructuredScriptTables(ip, port, script)
		for _, v := range structuredVulns {
			if !seenCVEs[v.CVEID] {
				seenCVEs[v.CVEID] = true
				vulns = append(vulns, v)
			}
		}

		// 2. Fallback text output regex parsing with anchored regex
		if script.Output != "" {
			lines := strings.Split(script.Output, "\n")
			for _, line := range lines {
				matches := anchoredCVERegex.FindStringSubmatch(line)
				if len(matches) > 1 && matches[1] != "" {
					cveMatch := matches[1]
					if !seenCVEs[cveMatch] {
						seenCVEs[cveMatch] = true

						var cvssScore float64
						if len(matches) > 2 && matches[2] != "" {
							cvssScore, _ = strconv.ParseFloat(matches[2], 64)
						}

						vulns = append(vulns, model.Vulnerability{
							DeviceIP:        ip,
							ServicePort:     port,
							CVEID:           cveMatch,
							Title:           fmt.Sprintf("Vulnerability in port %d (%s)", port, script.ID),
							Severity:        SeverityFromCVSS(cvssScore),
							CVSSScore:       cvssScore,
							Description:     strings.TrimSpace(line),
							ReferenceURL:    fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveMatch),
							Status:          "open",
							FirstDetectedAt: now,
							LastSeenAt:      now,
							DetectedAt:      now,
						})
					}
				}
			}
		}
	}

	return vulns
}

func parseStructuredScriptTables(ip string, port int, script NmapScript) []model.Vulnerability {
	var vulns []model.Vulnerability
	now := time.Now().UTC()

	var processTable func(tbl NmapTable)
	processTable = func(tbl NmapTable) {
		// 1. Gather non-CVE exploit IDs under this table
		var exploitRefs []string
		for _, sub := range tbl.Tables {
			var id, elemType, isExploit string
			for _, elem := range sub.Elems {
				switch elem.Key {
				case "id":
					id = elem.Value
				case "type":
					elemType = elem.Value
				case "is_exploit":
					isExploit = elem.Value
				}
			}
			if id == "" {
				id = sub.Key
			}

			if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
				if isExploit == "true" ||
					strings.HasPrefix(strings.ToUpper(id), "EDB-ID:") ||
					strings.HasPrefix(strings.ToUpper(id), "PACKETSTORM:") ||
					strings.HasPrefix(strings.ToUpper(id), "MSF:") ||
					elemType == "exploitdb" || elemType == "packetstorm" {
					exploitRefs = append(exploitRefs, id)
				}
			}
		}

		// 2. Extract CVE entries under this table
		for _, sub := range tbl.Tables {
			var id, elemType, isExploit string
			var cvssScore float64
			for _, elem := range sub.Elems {
				switch elem.Key {
				case "id":
					id = elem.Value
				case "type":
					elemType = elem.Value
				case "is_exploit":
					isExploit = elem.Value
				case "cvss":
					cvssScore, _ = strconv.ParseFloat(elem.Value, 64)
				}
			}
			if id == "" {
				id = sub.Key
			}

			isCVE := strings.HasPrefix(strings.ToUpper(id), "CVE-") ||
				strings.HasPrefix(strings.ToUpper(sub.Key), "CVE-") ||
				elemType == "cve"

			if isCVE {
				targetCVE := id
				if targetCVE == "" || !strings.HasPrefix(strings.ToUpper(targetCVE), "CVE-") {
					targetCVE = sub.Key
				}

				hasExploit := isExploit == "true" || len(exploitRefs) > 0
				var currentRefs []string
				if len(exploitRefs) > 0 {
					currentRefs = append([]string(nil), exploitRefs...)
				}

				vulns = append(vulns, model.Vulnerability{
					DeviceIP:        ip,
					ServicePort:     port,
					CVEID:           targetCVE,
					Title:           fmt.Sprintf("Vulnerability %s on port %d", targetCVE, port),
					Severity:        SeverityFromCVSS(cvssScore),
					CVSSScore:       cvssScore,
					Description:     fmt.Sprintf("Identified via %s script", script.ID),
					ReferenceURL:    fmt.Sprintf("https://vulners.com/cve/%s", targetCVE),
					IsExploit:       hasExploit,
					ExploitRefs:     currentRefs,
					Status:          "open",
					FirstDetectedAt: now,
					LastSeenAt:      now,
					DetectedAt:      now,
				})
			} else if len(sub.Tables) > 0 {
				processTable(sub)
			}
		}
	}

	for _, tbl := range script.Tables {
		processTable(tbl)
	}

	return vulns
}

// SeverityFromCVSS converts CVSS numeric score to severity tier.
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
