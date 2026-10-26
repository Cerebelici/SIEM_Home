package discovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/identity"
)

// nameLookupTimeout bounds each mDNS, NetBIOS and reverse DNS query. Phones and IoT devices
// on Wi-Fi in power save mode often need a few hundred milliseconds to answer.
const nameLookupTimeout = 300 * time.Millisecond

var (
	vendorDBMu sync.RWMutex
	vendorDB   map[string]string // upper-case hex prefix (6, 7 or 9 digits) -> vendor
)

// LoadVendorDatabase loads the IEEE OUI vendor list (nmap-mac-prefixes) that is installed
// with nmap, so vendor lookup covers every registered MAC prefix and not only the small
// built-in list. It returns the number of loaded prefixes.
func LoadVendorDatabase(nmapPath string) (int, error) {
	for _, candidate := range vendorDatabaseCandidates(nmapPath) {
		f, err := os.Open(candidate)
		if err != nil {
			continue
		}
		db, err := parseVendorDatabase(f)
		_ = f.Close()
		if err != nil || len(db) == 0 {
			continue
		}
		vendorDBMu.Lock()
		vendorDB = db
		vendorDBMu.Unlock()
		return len(db), nil
	}
	return 0, fmt.Errorf("nmap-mac-prefixes not found next to %q", nmapPath)
}

func vendorDatabaseCandidates(nmapPath string) []string {
	var dirs []string
	if dir := os.Getenv("NMAPDIR"); dir != "" {
		dirs = append(dirs, dir)
	}
	bins := []string{nmapPath}
	if real, err := filepath.EvalSymlinks(nmapPath); err == nil && real != nmapPath {
		bins = append(bins, real)
	}
	for _, bin := range bins {
		if bin == "" || !filepath.IsAbs(bin) {
			continue
		}
		binDir := filepath.Dir(bin)
		dirs = append(dirs, binDir, filepath.Join(binDir, "..", "share", "nmap"))
	}
	dirs = append(dirs, "/opt/homebrew/share/nmap", "/usr/local/share/nmap", "/opt/local/share/nmap", "/usr/share/nmap")

	paths := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		paths = append(paths, filepath.Join(dir, "nmap-mac-prefixes"))
	}
	return paths
}

func parseVendorDatabase(f *os.File) (map[string]string, error) {
	db := make(map[string]string, 52000)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, vendor, ok := strings.Cut(line, " ")
		vendor = strings.TrimSpace(vendor)
		if !ok || vendor == "" {
			continue
		}
		switch len(prefix) {
		case 6, 7, 9:
			db[strings.ToUpper(prefix)] = vendor
		}
	}
	return db, scanner.Err()
}

// lookupVendorDatabase returns the vendor for the longest matching registered prefix.
func lookupVendorDatabase(cleanMAC string) string {
	vendorDBMu.RLock()
	defer vendorDBMu.RUnlock()
	if vendorDB == nil {
		return ""
	}
	for _, n := range []int{9, 7, 6} {
		if len(cleanMAC) >= n {
			if vendor, ok := vendorDB[cleanMAC[:n]]; ok {
				return vendor
			}
		}
	}
	return ""
}

// usableHostname drops names that do not identify a device, such as the "localhost" that
// some devices announce over mDNS, or the IP address itself.
func usableHostname(name, ip string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	name = strings.TrimSuffix(name, ".local")
	switch strings.ToLower(name) {
	case "", "-", "localhost", "localhost.localdomain", ip:
		return ""
	}
	return name
}

// ResolveHostnameAndVendor enriches discovery findings with local network mDNS,
// NetBIOS, and reverse DNS PTR lookups, as well as signature-based vendor inference.
func ResolveHostnameAndVendor(ctx context.Context, ip string, currentHost, currentVendor, mac string) (string, string) {
	hostname := strings.TrimSpace(currentHost)
	vendor := strings.TrimSpace(currentVendor)

	hostname = usableHostname(hostname, ip)
	if vendor == "-" || strings.EqualFold(vendor, "unknown") {
		vendor = ""
	}

	// 1. Hostname Resolution (if missing)
	// Query mDNS, NetBIOS, and reverse DNS in parallel and keep the first usable answer.
	if hostname == "" {
		resCh := make(chan string, 3)

		// mDNS PTR query (Apple iOS/macOS & Android mDNS)
		go func() {
			if mdnsName := usableHostname(queryOrEmpty(QueryMDNSPTR(ctx, ip, nameLookupTimeout)), ip); mdnsName != "" {
				select {
				case resCh <- mdnsName:
				default:
				}
			}
		}()

		// NetBIOS node status query (Windows, Samba, Android SMB)
		go func() {
			if nbName := usableHostname(queryOrEmpty(QueryNetBIOS(ctx, ip, nameLookupTimeout)), ip); nbName != "" {
				select {
				case resCh <- nbName:
				default:
				}
			}
		}()

		// Standard reverse DNS lookup
		go func() {
			dnsCtx, cancel := context.WithTimeout(ctx, nameLookupTimeout)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(dnsCtx, ip)
			if err == nil && len(names) > 0 {
				if cleanName := usableHostname(names[0], ip); cleanName != "" {
					select {
					case resCh <- cleanName:
					default:
					}
				}
			}
		}()

		select {
		case name := <-resCh:
			hostname = name
		case <-time.After(nameLookupTimeout + 20*time.Millisecond):
		case <-ctx.Done():
		}
	}

	// 2. Vendor Inference
	// If vendor is missing OR if the MAC is a randomized/private address, infer vendor from resolved hostname
	normMAC := identity.NormalizeMAC(mac)
	isRandomMAC := normMAC != "" && identity.IsLocallyAdministered(normMAC)

	if vendor == "" || isRandomMAC {
		if inferred := InferVendorFromHostname(hostname); inferred != "" {
			vendor = inferred
		}
	}

	// 3. OUI Lookup if vendor is still missing and MAC is a globally unique IEEE address
	if vendor == "" && normMAC != "" && !isRandomMAC {
		if ouiVendor := LookupOUIPrefix(normMAC); ouiVendor != "" {
			vendor = ouiVendor
		}
	}

	return hostname, vendor
}

// InferVendorFromHostname identifies hardware vendors from device naming patterns.
func InferVendorFromHostname(hostname string) string {
	if hostname == "" {
		return ""
	}
	lower := strings.ToLower(hostname)

	switch {
	// Apple
	case strings.Contains(lower, "iphone"),
		strings.Contains(lower, "ipad"),
		strings.Contains(lower, "ipod"),
		strings.Contains(lower, "macbook"),
		strings.Contains(lower, "imac"),
		strings.Contains(lower, "macmini"),
		strings.Contains(lower, "macstudio"),
		strings.Contains(lower, "macpro"),
		strings.Contains(lower, "apple-tv"),
		strings.Contains(lower, "appletv"),
		strings.Contains(lower, "airpods"),
		strings.Contains(lower, "homepod"),
		strings.Contains(lower, "apple"):
		return "Apple, Inc."

	// Samsung
	case strings.Contains(lower, "galaxy"),
		strings.Contains(lower, "samsung"),
		strings.HasPrefix(lower, "sm-"):
		return "Samsung Electronics"

	// Google
	case strings.Contains(lower, "pixel"),
		strings.Contains(lower, "chromecast"),
		strings.Contains(lower, "google"),
		strings.Contains(lower, "nest-hub"),
		strings.Contains(lower, "nest-mini"):
		return "Google LLC"

	// Xiaomi / Redmi / Poco
	case strings.Contains(lower, "xiaomi"),
		strings.Contains(lower, "redmi"),
		strings.Contains(lower, "poco"):
		return "Xiaomi Communications"

	// Huawei / Honor
	case strings.Contains(lower, "huawei"),
		strings.Contains(lower, "honor"):
		return "Huawei Device Co."

	// OnePlus
	case strings.Contains(lower, "oneplus"):
		return "OnePlus Electronics"

	// Sony
	case strings.Contains(lower, "playstation"),
		strings.Contains(lower, "ps4"),
		strings.Contains(lower, "ps5"),
		strings.Contains(lower, "bravia"),
		strings.Contains(lower, "sony"):
		return "Sony Interactive Entertainment"

	// Nintendo
	case strings.Contains(lower, "nintendo"),
		strings.Contains(lower, "switch"):
		return "Nintendo Co., Ltd."

	// Amazon
	case strings.Contains(lower, "kindle"),
		strings.Contains(lower, "firetv"),
		strings.Contains(lower, "echo-"),
		strings.Contains(lower, "amazon"):
		return "Amazon Technologies"

	// Microsoft
	case strings.Contains(lower, "xbox"),
		strings.Contains(lower, "surface"):
		return "Microsoft Corporation"

	// Network Appliance Vendors
	case strings.Contains(lower, "mikrotik"),
		strings.Contains(lower, "routeros"):
		return "MikroTik"
	case strings.Contains(lower, "ubiquiti"),
		strings.Contains(lower, "unifi"),
		strings.Contains(lower, "edgerouter"),
		strings.Contains(lower, "amplifi"):
		return "Ubiquiti Networks"
	case strings.Contains(lower, "tplink"),
		strings.Contains(lower, "tp-link"),
		strings.Contains(lower, "archer"),
		strings.Contains(lower, "deco"):
		return "TP-Link Technologies"
	case strings.Contains(lower, "asus"),
		strings.Contains(lower, "zenwifi"):
		return "ASUSTeK Computer"
	case strings.Contains(lower, "netgear"),
		strings.Contains(lower, "nighthawk"),
		strings.Contains(lower, "orbi"):
		return "NETGEAR Inc."
	case strings.Contains(lower, "fritz"),
		strings.Contains(lower, "avm"):
		return "AVM GmbH"
	case strings.Contains(lower, "synology"),
		strings.Contains(lower, "diskstation"):
		return "Synology Inc."
	case strings.Contains(lower, "qnap"):
		return "QNAP Systems"
	case strings.Contains(lower, "espressif"),
		strings.HasPrefix(lower, "esp_"),
		strings.HasPrefix(lower, "esp32"),
		strings.HasPrefix(lower, "esp8266"):
		return "Espressif Systems"
	case strings.Contains(lower, "sonos"):
		return "Sonos, Inc."
	case strings.Contains(lower, "roku"):
		return "Roku, Inc."
	case strings.Contains(lower, "webos"),
		strings.Contains(lower, "lgwebostv"):
		return "LG Electronics"
	}

	return ""
}

// QueryMDNSPTR sends an mDNS reverse PTR query to discover hostname.
func QueryMDNSPTR(ctx context.Context, targetIP string, timeout time.Duration) (string, error) {
	ip := net.ParseIP(targetIP).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid IPv4 address")
	}

	query, err := buildMDNSPTRQuery(ip)
	if err != nil {
		return "", err
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send to multicast mDNS group
	mcastAddr := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	_, _ = conn.WriteToUDP(query, mcastAddr)

	// Also send unicast directly to target port 5353
	unicastAddr := &net.UDPAddr{IP: ip, Port: 5353}
	_, _ = conn.WriteToUDP(query, unicastAddr)

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			return "", err
		}

		// Verify sender IP matches target
		udpSrc, ok := src.(*net.UDPAddr)
		if ok && !udpSrc.IP.Equal(ip) {
			continue
		}

		name, err := parseMDNSPTRResponse(buf[:n])
		if err == nil && name != "" {
			return name, nil
		}
	}
}

func buildMDNSPTRQuery(ip net.IP) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x00}) // ID
	buf.Write([]byte{0x00, 0x00}) // Flags
	buf.Write([]byte{0x00, 0x01}) // QDCOUNT = 1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	labels := []string{
		fmt.Sprintf("%d", ip[3]),
		fmt.Sprintf("%d", ip[2]),
		fmt.Sprintf("%d", ip[1]),
		fmt.Sprintf("%d", ip[0]),
		"in-addr",
		"arpa",
	}

	for _, l := range labels {
		buf.WriteByte(byte(len(l)))
		buf.WriteString(l)
	}
	buf.WriteByte(0x00)

	buf.Write([]byte{0x00, 0x0c}) // Type: PTR
	buf.Write([]byte{0x80, 0x01}) // Class: IN + Unicast Response

	return buf.Bytes(), nil
}

func parseDNSName(data []byte, offset int) (string, int, error) {
	var parts []string
	curr := offset
	jumped := false
	jumpEnd := 0
	depth := 0

	for curr < len(data) && depth < 20 {
		depth++
		length := int(data[curr])
		if length == 0 {
			if !jumped {
				jumpEnd = curr + 1
			}
			break
		}
		if (length & 0xc0) == 0xc0 {
			if curr+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated pointer")
			}
			ptr := int(binary.BigEndian.Uint16(data[curr:curr+2]) & 0x3fff)
			if !jumped {
				jumpEnd = curr + 2
				jumped = true
			}
			curr = ptr
			continue
		}

		curr++
		if curr+length > len(data) {
			return "", 0, fmt.Errorf("label out of range")
		}
		parts = append(parts, string(data[curr:curr+length]))
		curr += length
		if !jumped {
			jumpEnd = curr
		}
	}

	if !jumped {
		jumpEnd = curr + 1
	}
	return strings.Join(parts, "."), jumpEnd, nil
}

func parseMDNSPTRResponse(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("response too short")
	}
	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))
	offset := 12

	for i := 0; i < qdCount; i++ {
		_, next, err := parseDNSName(data, offset)
		if err != nil {
			return "", err
		}
		offset = next + 4
		if offset > len(data) {
			return "", fmt.Errorf("truncated question")
		}
	}

	for i := 0; i < anCount; i++ {
		if offset >= len(data) {
			break
		}
		_, next, err := parseDNSName(data, offset)
		if err != nil {
			return "", err
		}
		offset = next
		if offset+10 > len(data) {
			break
		}
		rrType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10

		if rrType == 12 { // PTR record
			ptrName, _, err := parseDNSName(data, offset)
			if err == nil && ptrName != "" {
				name := strings.TrimSuffix(ptrName, ".local")
				name = strings.TrimSuffix(name, ".local.")
				name = strings.TrimSuffix(name, ".")
				return name, nil
			}
		}
		offset += rdLength
	}

	return "", fmt.Errorf("no PTR record found")
}

// QueryNetBIOS queries UDP port 137 for NetBIOS node status.
func QueryNetBIOS(ctx context.Context, targetIP string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(targetIP, "137"), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// NetBIOS Node Status Request wildcard packet
	query := []byte{
		0x13, 0x37, // Transaction ID
		0x00, 0x00, // Flags: Standard Query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// Question Name: * space-padded (encoded as CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
		0x00, 0x21, // Type: NBSTAT (33)
		0x00, 0x01, // Class: IN
	}

	if _, err := conn.Write(query); err != nil {
		return "", err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return "", err
	}

	// In NBSTAT response, number of names is at offset 56
	numNames := int(buf[56])
	if numNames <= 0 || 57+numNames*18 > n {
		return "", fmt.Errorf("invalid NetBIOS response")
	}

	for i := 0; i < numNames; i++ {
		nameOffset := 57 + i*18
		rawName := strings.TrimSpace(string(buf[nameOffset : nameOffset+15]))
		nameType := buf[nameOffset+15]
		// Type 0x00 is Workstation / Computer Name
		if nameType == 0x00 && rawName != "" && !strings.HasPrefix(rawName, "IS~") {
			return rawName, nil
		}
	}

	return "", fmt.Errorf("no NetBIOS workstation name found")
}

// queryOrEmpty returns name when the lookup succeeded, or "" when it failed.
func queryOrEmpty(name string, err error) string {
	if err != nil {
		return ""
	}
	return name
}

// LookupOUIPrefix returns the vendor registered for the MAC address prefix. It uses the
// nmap vendor database when LoadVendorDatabase found it, else a small built-in list.
func LookupOUIPrefix(mac string) string {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
	if len(clean) < 6 {
		return ""
	}
	if vendor := lookupVendorDatabase(clean); vendor != "" {
		return vendor
	}
	prefix := clean[:6]

	ouiMap := map[string]string{
		"000393": "Apple, Inc.",
		"000502": "Apple, Inc.",
		"000A27": "Apple, Inc.",
		"000A95": "Apple, Inc.",
		"000D93": "Apple, Inc.",
		"0010FA": "Apple, Inc.",
		"001124": "Apple, Inc.",
		"001451": "Apple, Inc.",
		"0016CB": "Apple, Inc.",
		"0017F2": "Apple, Inc.",
		"0019E3": "Apple, Inc.",
		"001B63": "Apple, Inc.",
		"001C42": "Parallels, Inc.",
		"001CBE": "Apple, Inc.",
		"001D4F": "Apple, Inc.",
		"001E52": "Apple, Inc.",
		"001F5B": "Apple, Inc.",
		"001FF3": "Apple, Inc.",
		"0021E9": "Apple, Inc.",
		"002241": "Apple, Inc.",
		"002312": "Apple, Inc.",
		"002332": "Apple, Inc.",
		"00236C": "Apple, Inc.",
		"0023DF": "Apple, Inc.",
		"002436": "Apple, Inc.",
		"002500": "Apple, Inc.",
		"00254B": "Apple, Inc.",
		"0025BC": "Apple, Inc.",
		"002608": "Apple, Inc.",
		"00264A": "Apple, Inc.",
		"0026B0": "Apple, Inc.",
		"0026BB": "Apple, Inc.",
		"00000C": "Cisco Systems",
		"000142": "Cisco Systems",
		"000143": "Cisco Systems",
		"0001C7": "Cisco Systems",
		"0001C9": "Cisco Systems",
		"000216": "Cisco Systems",
		"00000E": "Fujitsu",
		"00000F": "Next, Inc.",
		"00001B": "Novell",
		"000039": "Toshiba",
		"000048": "Seiko Epson",
		"000086": "Megahertz",
		"0002B3": "Intel Corporation",
		"000423": "Intel Corporation",
		"0007E9": "Intel Corporation",
		"000E0C": "Intel Corporation",
		"001302": "Intel Corporation",
		"0013E8": "Intel Corporation",
		"001500": "Intel Corporation",
		"0016EA": "Intel Corporation",
		"000C29": "VMware, Inc.",
		"000569": "VMware, Inc.",
		"005056": "VMware, Inc.",
		"080027": "Oracle VirtualBox",
		"525400": "QEMU / KVM",
		"B827EB": "Raspberry Pi Foundation",
		"DCA632": "Raspberry Pi Foundation",
		"E45F01": "Raspberry Pi Foundation",
		"28CDC4": "Raspberry Pi Foundation",
		"2462AB": "Espressif Systems",
		"240AC4": "Espressif Systems",
		"30AEA4": "Espressif Systems",
		"84F3EB": "Espressif Systems",
		"A4CF12": "Espressif Systems",
		"CC50E3": "Espressif Systems",
		"483FDA": "MikroTik",
		"6C3B6B": "MikroTik",
		"CC2DE0": "MikroTik",
		"085531": "MikroTik",
		"18FD74": "MikroTik",
		"2C6B7D": "MikroTik",
		"D401C3": "MikroTik",
		"789A18": "MikroTik",
		"B869F4": "Ubiquiti Networks",
		"F09FC2": "Ubiquiti Networks",
		"24A43C": "Ubiquiti Networks",
		"802AA8": "Ubiquiti Networks",
		"002722": "Ubiquiti Networks",
		"AC8B19": "Ubiquiti Networks",
		"5004B8": "TP-Link Technologies",
		"60A44C": "TP-Link Technologies",
		"704F57": "TP-Link Technologies",
		"E848B8": "TP-Link Technologies",
		"F4EC38": "TP-Link Technologies",
		"001D0F": "TP-Link Technologies",
		"002719": "TP-Link Technologies",
	}

	return ouiMap[prefix]
}
