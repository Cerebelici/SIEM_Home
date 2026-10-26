package netdetect

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// virtualInterfacePrefixes contains interface name prefixes to ignore by default.
var virtualInterfacePrefixes = []string{
	"docker", "br-", "veth", "virbr", "vboxnet", "vmnet",
	"utun", "awdl", "llw", "tun", "tap", "wg", "tailscale", "bridge",
}

// isIgnoredInterface checks if the interface name matches common virtual/tunnel names.
func isIgnoredInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// detectDefaultOutboundIP resolves the local IPv4 used to route traffic outside.
func detectDefaultOutboundIP() string {
	conn, err := net.DialTimeout("udp4", "1.1.1.1:80", 1200*time.Millisecond)
	if err != nil {
		conn, err = net.DialTimeout("udp4", "8.8.8.8:80", 1200*time.Millisecond)
	}
	if err != nil {
		return ""
	}
	defer conn.Close()

	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	return ""
}

// ListActiveInterfaces returns all active non-loopback network interfaces with an assigned IPv4 subnet.
func ListActiveInterfaces() ([]model.NetworkInterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}

	defaultIP := detectDefaultOutboundIP()
	var results []model.NetworkInterfaceInfo

	for _, iface := range ifaces {
		// Filter out down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Filter out known virtual/tunnel bridges unless it happens to match the outbound route
		isVirtual := isIgnoredInterface(iface.Name)

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}

			// Exclude link-local addresses (169.254.0.0/16)
			if ipv4.IsLinkLocalUnicast() || ipv4[0] == 169 && ipv4[1] == 254 {
				continue
			}

			ipStr := ipv4.String()
			isDefault := (defaultIP != "" && ipStr == defaultIP)

			// If it's a virtual interface and NOT the default route, skip it
			if isVirtual && !isDefault {
				continue
			}

			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones == 0 {
				continue
			}

			// Compute network CIDR
			addrPrefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", ipStr, ones))
			cidrStr := ""
			if err == nil {
				cidrStr = addrPrefix.Masked().String()
			} else {
				networkIP := ipv4.Mask(ipNet.Mask)
				cidrStr = fmt.Sprintf("%s/%d", networkIP.String(), ones)
			}

			results = append(results, model.NetworkInterfaceInfo{
				Name:      iface.Name,
				IPv4:      ipStr,
				CIDR:      cidrStr,
				MAC:       iface.HardwareAddr.String(),
				IsDefault: isDefault,
			})
		}
	}

	return results, nil
}

// DetectDefaultNetwork selects the active network interface and CIDR to scan.
// It prioritizes the interface that routes outbound traffic.
func DetectDefaultNetwork() (*model.NetworkInterfaceInfo, error) {
	ifaces, err := ListActiveInterfaces()
	if err != nil {
		return nil, err
	}

	if len(ifaces) == 0 {
		return nil, errors.New("no active IPv4 network interface found")
	}

	// 1. Look for the interface marked as default
	for _, iface := range ifaces {
		if iface.IsDefault {
			copy := iface
			return &copy, nil
		}
	}

	// 2. Fall back to the first non-virtual active interface
	for _, iface := range ifaces {
		if !isIgnoredInterface(iface.Name) {
			copy := iface
			return &copy, nil
		}
	}

	// 3. Fall back to first available interface
	copy := ifaces[0]
	return &copy, nil
}
