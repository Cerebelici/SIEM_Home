package netdetect

import (
	"strings"
	"testing"
)

func TestParseDarwinRouteGateway(t *testing.T) {
	out := `   route to: default
destination: default
       mask: default
    gateway: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	got, err := parseDarwinRouteGateway(out)
	if err != nil || got != "192.168.0.1" {
		t.Errorf("parseDarwinRouteGateway() = %q, %v; want 192.168.0.1", got, err)
	}

	if _, err := parseDarwinRouteGateway("route: writing to routing socket: not in table\n"); err == nil {
		t.Errorf("expected an error without a gateway line")
	}
}

func TestParseLinuxRouteGateway(t *testing.T) {
	table := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	0000A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
`
	got, err := parseLinuxRouteGateway(strings.NewReader(table))
	if err != nil || got != "192.168.0.1" {
		t.Errorf("parseLinuxRouteGateway() = %q, %v; want 192.168.0.1", got, err)
	}
}
