package netdetect

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrLocalNetworkDenied reports that the operating system does not let this app reach the local network.
var ErrLocalNetworkDenied = errors.New("macOS is blocking local network access for Cerberus Sentinel. " +
	"Allow it in System Settings > Privacy & Security > Local Network, then trigger a discovery scan")

// localNetworkProbePort is a TCP port that most home routers answer (DNS). A refused or
// timed out connection is fine: only the error the OS returns before sending a packet matters.
const localNetworkProbePort = "53"

// DefaultGateway returns the IPv4 address of the default route gateway.
func DefaultGateway() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
		if err != nil {
			return "", fmt.Errorf("reading default route: %w", err)
		}
		return parseDarwinRouteGateway(string(out))
	case "linux":
		f, err := os.Open("/proc/net/route")
		if err != nil {
			return "", fmt.Errorf("reading default route: %w", err)
		}
		defer f.Close()
		return parseLinuxRouteGateway(f)
	default:
		return "", fmt.Errorf("default gateway lookup not supported on %s", runtime.GOOS)
	}
}

func parseDarwinRouteGateway(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || key != "gateway" {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("default gateway %q is not an IPv4 address", strings.TrimSpace(value))
		}
		return ip.To4().String(), nil
	}
	return "", errors.New("no default gateway")
}

func parseLinuxRouteGateway(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Iface Destination Gateway Flags ...; the default route has destination 00000000.
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		raw, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil || raw == 0 {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(raw))
		return ip.String(), nil
	}
	return "", errors.New("no default gateway")
}

// ProbeLocalNetwork opens a TCP connection to host and returns ErrLocalNetworkDenied when the
// OS refuses to send it. macOS Local Network privacy fails such connections at once with
// EHOSTUNREACH while the user has not allowed access (Apple TN3179). Any other result
// (connected, refused, timed out) means the packet left the machine.
func ProbeLocalNetwork(ctx context.Context, host string) error {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(host, localNetworkProbePort))
	if err == nil {
		_ = conn.Close()
		return nil
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return ErrLocalNetworkDenied
	}
	return nil
}

// WaitForLocalNetworkAccess makes sure macOS lets this app reach the local network before a
// scan starts. The first probe also makes macOS show its permission prompt. While access is
// blocked, it probes the default gateway again every few seconds until wait expires, so a
// user who answers the prompt does not get an empty first scan. Other platforms have no such
// permission and return nil at once.
func WaitForLocalNetworkAccess(ctx context.Context, wait time.Duration) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	gateway, err := DefaultGateway()
	if err != nil {
		// Without a gateway there is nothing safe to probe; let the scan decide.
		return nil
	}

	deadline := time.Now().Add(wait)
	for attempt := 0; ; attempt++ {
		if err := ProbeLocalNetwork(ctx, gateway); !errors.Is(err, ErrLocalNetworkDenied) {
			if attempt > 0 {
				log.Printf("[NetDetect] Local network access granted.")
			}
			return nil
		}
		if attempt == 0 {
			log.Printf("[NetDetect] Warning: macOS blocks local network access. Waiting up to %s for the user to allow Cerberus Sentinel.", wait)
		}
		if time.Now().After(deadline) {
			return ErrLocalNetworkDenied
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
