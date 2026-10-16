package scanner

import "encoding/xml"

// NmapRun represents the root of the Nmap XML output.
type NmapRun struct {
	XMLName  xml.Name   `xml:"nmaprun"`
	Scanner  string     `xml:"scanner,attr"`
	Args     string     `xml:"args,attr"`
	Start    int64      `xml:"start,attr"`
	Version  string     `xml:"version,attr"`
	Hosts    []NmapHost `xml:"host"`
	RunStats RunStats   `xml:"runstats"`
}

// NmapHost represents a single scanned host.
type NmapHost struct {
	StartTime   int64          `xml:"starttime,attr"`
	EndTime     int64          `xml:"endtime,attr"`
	Status      NmapStatus     `xml:"status"`
	Addresses   []NmapAddress  `xml:"address"`
	Hostnames   []NmapHostname `xml:"hostnames>hostname"`
	Ports       []NmapPort     `xml:"ports>port"`
	HostScripts []NmapScript   `xml:"hostscript>script"`
}

// NmapStatus represents host up/down status.
type NmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// NmapAddress represents an IP or MAC address.
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // "ipv4", "ipv6", "mac"
	Vendor   string `xml:"vendor,attr"`
}

// NmapHostname represents a hostname found for a host.
type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// NmapPort represents a scanned port on the host.
type NmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    NmapState    `xml:"state"`
	Service  NmapService  `xml:"service"`
	Scripts  []NmapScript `xml:"script"`
}

// NmapState represents port state (open, closed, filtered).
type NmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// NmapService represents service information detected on the port.
type NmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Method    string `xml:"method,attr"`
	Conf      int    `xml:"conf,attr"`
}

// NmapScript represents an NSE script execution result.
type NmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Tables []NmapTable `xml:"table"`
	Elems  []NmapElem  `xml:"elem"`
}

// NmapTable represents nested tables in NSE script output.
type NmapTable struct {
	Key    string      `xml:"key,attr"`
	Tables []NmapTable `xml:"table"`
	Elems  []NmapElem  `xml:"elem"`
}

// NmapElem represents key-value elements in NSE script output.
type NmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// RunStats contains run statistics from Nmap.
type RunStats struct {
	Finished struct {
		Time    int64   `xml:"time,attr"`
		Summary string  `xml:"summary,attr"`
		Elapsed float64 `xml:"elapsed,attr"`
		Exit    string  `xml:"exit,attr"`
	} `xml:"finished"`
	Hosts struct {
		Up    int `xml:"up,attr"`
		Down  int `xml:"down,attr"`
		Total int `xml:"total,attr"`
	} `xml:"hosts"`
}
