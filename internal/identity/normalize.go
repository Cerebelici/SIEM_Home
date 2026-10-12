package identity

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gr0gu/cerberus/internal/model"
)

var genericHostnames = map[string]bool{
	"localhost": true,
	"iphone":    true,
	"espressif": true,
}

// NormalizeMAC standardizes MAC addresses to lowercase colon-delimited format (xx:xx:xx:xx:xx:xx).
// Returns an empty string if the MAC address cannot be parsed.
func NormalizeMAC(mac string) string {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return ""
	}
	// Support both colon and hyphen delimiters
	mac = strings.ReplaceAll(mac, "-", ":")
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 6 {
		return ""
	}
	// Standardize to 6 octets
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])
}

// IsLocallyAdministered returns true if the locally-administered address (LAA) bit is set
// in the first octet (bit 1), indicating a randomized or private MAC address.
func IsLocallyAdministered(mac string) bool {
	norm := NormalizeMAC(mac)
	if norm == "" || len(norm) < 2 {
		return false
	}
	firstByte, err := strconv.ParseUint(norm[:2], 16, 8)
	if err != nil {
		return false
	}
	return (firstByte & 0x02) != 0
}

// OUI returns the Organizationally Unique Identifier (first 3 octets, "xx:xx:xx").
// Returns empty string if the MAC is invalid or locally-administered / randomized.
func OUI(mac string) string {
	if IsLocallyAdministered(mac) {
		return ""
	}
	norm := NormalizeMAC(mac)
	if norm == "" || len(norm) < 8 {
		return ""
	}
	return norm[:8]
}

// NormalizeHostname lowercases, strips domain suffixes, and filters generic hostnames.
// Returns empty string if the name is generic or blank.
func NormalizeHostname(hostname string) string {
	name := strings.TrimSpace(strings.ToLower(hostname))
	if name == "" {
		return ""
	}

	// Strip domain suffix (everything after first dot)
	if idx := strings.IndexByte(name, '.'); idx != -1 {
		name = name[:idx]
	}

	// Filter generic names (localhost, android-*, iphone, espressif)
	if genericHostnames[name] || strings.HasPrefix(name, "android-") {
		return ""
	}

	return name
}

// PortProfile builds a sorted set of "proto/port/service_name" and returns its SHA-256 hash.
func PortProfile(services []model.Service) ([]string, string) {
	if len(services) == 0 {
		return []string{}, ""
	}

	set := make(map[string]bool)
	for _, s := range services {
		proto := strings.ToLower(strings.TrimSpace(s.Protocol))
		if proto == "" {
			proto = "tcp"
		}
		svcName := strings.ToLower(strings.TrimSpace(s.ServiceName))
		tag := fmt.Sprintf("%s/%d/%s", proto, s.Port, svcName)
		set[tag] = true
	}

	profile := make([]string, 0, len(set))
	for p := range set {
		profile = append(profile, p)
	}
	sort.Strings(profile)

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(profile, ","))))
	return profile, hash
}

// Jaccard computes the Jaccard similarity index (Intersection over Union) of two string sets.
// Returns 0.0 if either set is empty.
func Jaccard(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	mapA := make(map[string]bool, len(a))
	for _, item := range a {
		mapA[item] = true
	}

	unionMap := make(map[string]bool, len(a)+len(b))
	for k := range mapA {
		unionMap[k] = true
	}

	intersection := 0
	for _, item := range b {
		unionMap[item] = true
		if mapA[item] {
			intersection++
		}
	}

	union := len(unionMap)
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

