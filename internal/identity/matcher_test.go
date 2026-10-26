package identity

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

type fakeCandidateStore struct {
	candidates []Candidate
}

func (f *fakeCandidateStore) GetCandidates(ctx context.Context, window time.Duration) ([]Candidate, error) {
	return f.candidates, nil
}

func TestNormalize_Functions(t *testing.T) {
	// 1. MAC normalization
	if got := NormalizeMAC("00-11-22-AA-BB-CC"); got != "00:11:22:aa:bb:cc" {
		t.Errorf("NormalizeMAC hyphen failed, got: %s", got)
	}
	if got := NormalizeMAC("invalid"); got != "" {
		t.Errorf("expected empty string for invalid MAC, got: %s", got)
	}

	// 2. Locally Administered Address (LAA) bit
	// 02:xx (bit 1 is set) -> LAA/random
	if !IsLocallyAdministered("da:4b:53:93:3c:51") {
		t.Errorf("expected da:... to be locally administered")
	}
	// 00:xx (bit 1 is not set) -> UAA
	if IsLocallyAdministered("00:11:22:33:44:55") {
		t.Errorf("expected 00:... to be UAA")
	}

	// 3. OUI
	if got := OUI("00:11:22:33:44:55"); got != "00:11:22" {
		t.Errorf("expected OUI 00:11:22, got %s", got)
	}
	if got := OUI("da:4b:53:93:3c:51"); got != "" {
		t.Errorf("expected empty OUI for random MAC, got %s", got)
	}

	// 4. Hostname normalization
	if got := NormalizeHostname("printer-1.corp.internal"); got != "printer-1" {
		t.Errorf("expected printer-1, got %s", got)
	}
	if got := NormalizeHostname("localhost"); got != "" {
		t.Errorf("expected generic localhost to be filtered out, got %s", got)
	}
	if got := NormalizeHostname("android-9912"); got != "" {
		t.Errorf("expected android-* to be filtered out, got %s", got)
	}

	// 5. PortProfile and Jaccard
	svcs := []model.Service{
		{Protocol: "tcp", Port: 80, ServiceName: "http"},
		{Protocol: "tcp", Port: 443, ServiceName: "https"},
	}
	prof, hash := PortProfile(svcs)
	if len(prof) != 2 || hash == "" {
		t.Errorf("expected 2 port entries and valid hash, got %v / %s", prof, hash)
	}

	j := Jaccard([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	// 2 intersection / 4 union = 0.5
	if j != 0.5 {
		t.Errorf("expected Jaccard 0.5, got %f", j)
	}

	// 6. Fingerprint normalization & comparison
	fps := NormalizeFingerprints([]string{" SSH-HOSTKEY:SHA256:ABC ", "ssl-cert:deadbeef", "ssh-hostkey:sha256:abc"})
	if len(fps) != 2 {
		t.Errorf("expected 2 deduplicated fingerprints, got %v", fps)
	}
	if !HasSharedFingerprint(fps, []string{"SSL-CERT:DEADBEEF"}) {
		t.Errorf("expected shared fingerprint match")
	}
}

func TestMatcher_DHCPMove(t *testing.T) {
	// Device D at .10 with UAA MAC M is later observed at .23 with MAC M -> binds to D
	uaaMAC := "00:11:22:33:44:55"
	dID := int64(10)
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:          dID,
				CurrentIP:   "10.0.0.10",
				MAC:         uaaMAC,
				MACIsRandom: false,
				LastSeen:    now.Add(-1 * time.Hour),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.23",
		MAC:        uaaMAC,
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != dID {
		t.Fatalf("expected bind to device %d, got %+v", dID, dec)
	}
	if dec.Reason != "uaa_mac" {
		t.Errorf("expected reason uaa_mac, got %s", dec.Reason)
	}
}

func TestMatcher_IPReuse(t *testing.T) {
	// D at .10 (hostname printer), seen 3 days ago (> 24h lease).
	// New observation at .10, hostname laptop-anna, no MAC -> score 10 - 15 = -5 < 50 -> new device, runner-up D.
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	dID := int64(20)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:        dID,
				CurrentIP: "10.0.0.10",
				Hostname:  "printer",
				LastSeen:  now.Add(-72 * time.Hour), // 3 days ago
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.10",
		Hostname:   "laptop-anna",
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionCreateNew {
		t.Fatalf("expected create_new for IP reuse with conflicting hostname, got %+v", dec)
	}
	if dec.RunnerUpDeviceID == nil || *dec.RunnerUpDeviceID != dID {
		t.Errorf("expected runner-up device %d, got %v", dID, dec.RunnerUpDeviceID)
	}
}

func TestMatcher_RandomMAC(t *testing.T) {
	// Observation with LAA MAC da:... equal to D's, same IP within 24h lease -> 40 + 30 = 70 -> binds to D
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	laaMAC := "da:4b:53:93:3c:51"
	dID := int64(30)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:          dID,
				CurrentIP:   "10.0.0.15",
				MAC:         laaMAC,
				MACIsRandom: true,
				LastSeen:    now.Add(-2 * time.Hour),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.15",
		MAC:        laaMAC,
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != dID {
		t.Fatalf("expected bind to device %d, got %+v", dID, dec)
	}
	if dec.Score != 70.0 {
		t.Errorf("expected score 70.0, got %f", dec.Score)
	}
}

func TestMatcher_Tier1_CryptoFingerprint(t *testing.T) {
	// Device changes BOTH IP (.10 -> .88) and randomized MAC (da:11:... -> da:22:...),
	// but presents the same SSH host key fingerprint -> Tier 1 deterministic bind!
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	dID := int64(101)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:           dID,
				CurrentIP:    "10.0.0.10",
				MAC:          "da:11:22:33:44:55",
				MACIsRandom:  true,
				Fingerprints: []string{"ssh-hostkey:sha256:abcd1234efgh5678"},
				LastSeen:     now.Add(-4 * time.Hour),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:           "10.0.0.88",
		MAC:          "da:22:33:44:55:66",
		Fingerprints: []string{"ssh-hostkey:sha256:abcd1234efgh5678"},
		ObservedAt:   now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != dID {
		t.Fatalf("expected Tier 1 crypto_fingerprint bind to %d, got %+v", dID, dec)
	}
	if dec.Reason != "crypto_fingerprint" || dec.Score != 100.0 {
		t.Errorf("expected reason crypto_fingerprint and score 100.0, got %s (%f)", dec.Reason, dec.Score)
	}
}

func TestMatcher_Tier2_RandomMAC_DHCPMove(t *testing.T) {
	// Phone/laptop with Per-SSID randomized MAC da:4b:53:93:3c:51 reconnects on a new DHCP IP (.15 -> .92)
	// during a -sn discovery scan (no ports/hostname yet) -> scores 40 + 15 = 55 >= 50 -> binds to D!
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	laaMAC := "da:4b:53:93:3c:51"
	dID := int64(102)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:          dID,
				CurrentIP:   "10.0.0.15",
				MAC:         laaMAC,
				MACIsRandom: true,
				LastSeen:    now.Add(-3 * time.Hour),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.92",
		MAC:        laaMAC,
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != dID {
		t.Fatalf("expected Tier 2 Per-SSID LAA MAC bind to %d across DHCP move, got %+v", dID, dec)
	}
	if dec.Score != 55.0 {
		t.Errorf("expected score 55.0 (40 MAC + 15 LAAMACMove), got %f", dec.Score)
	}
}

func TestMatcher_Tier3_DeferredServiceMatchOverProvisionalStub(t *testing.T) {
	// Device #10 (at .10) rotated its MAC and moved to .88.
	// Discovery (-sn) created provisional stub #99 at .88 (Confidence 0.3, Ports empty).
	// Vulnerability scan (-sV) then completes on .88 and reveals Hostname "media-srv" + Ports [80, 443].
	// Matcher must bind to historical Device #10 instead of provisional stub #99.
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	origID := int64(10)
	stubID := int64(99)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:                 stubID,
				CurrentIP:          "10.0.0.88",
				MAC:                "da:99:88:77:66:55",
				MACIsRandom:        true,
				IdentityConfidence: 0.3,
				Ports:              nil,
				LastSeen:           now.Add(-5 * time.Second),
			},
			{
				ID:                 origID,
				CurrentIP:          "10.0.0.10",
				MAC:                "da:11:22:33:44:55",
				MACIsRandom:        true,
				Hostname:           "media-srv",
				Ports:              []string{"tcp/80/http", "tcp/443/https"},
				IdentityConfidence: 0.8,
				LastSeen:           now.Add(-2 * time.Hour),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.88",
		MAC:        "da:99:88:77:66:55",
		Hostname:   "media-srv",
		Ports:      []string{"tcp/80/http", "tcp/443/https"},
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != origID {
		t.Fatalf("expected Tier 3 deferred service match to original device %d, got %+v", origID, dec)
	}
	if dec.Reason != "deferred_service_match" {
		t.Errorf("expected reason deferred_service_match, got %s", dec.Reason)
	}
}

func TestMatcher_UnprivilegedIPOnlyLease(t *testing.T) {
	// When running in unprivileged mode (-sT), Nmap may return an active IP with no MAC,
	// no hostname, and no open ports yet. Within the 24h lease window, it must bind to the
	// existing device at that IP (30 IPLease + 20 IPOnlyLease = 50) instead of duplicating.
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	dID := int64(200)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:        dID,
				CurrentIP: "172.28.0.50",
				LastSeen:  now.Add(-10 * time.Minute),
			},
			{
				ID:        int64(199),
				CurrentIP: "172.28.0.50",
				LastSeen:  now.Add(-20 * time.Minute),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "172.28.0.50",
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != dID {
		t.Fatalf("expected bind to most recent device %d at 172.28.0.50, got %+v", dID, dec)
	}
	if dec.Score != 50.0 {
		t.Errorf("expected score 50.0, got %f", dec.Score)
	}
}

func TestMatcher_VetoDifferentUAAMACs(t *testing.T) {
	// Different UAA MACs on same IP -> vetoed, never bound
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	uaaMAC1 := "00:11:22:33:44:01"
	uaaMAC2 := "00:11:22:33:44:02"

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:          int64(40),
				CurrentIP:   "10.0.0.50",
				MAC:         uaaMAC1,
				MACIsRandom: false,
				LastSeen:    now.Add(-10 * time.Minute),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.50",
		MAC:        uaaMAC2,
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionCreateNew {
		t.Fatalf("expected create_new due to UAA MAC veto, got %+v", dec)
	}
}

func TestMatcher_AmbiguityThresholdMargin(t *testing.T) {
	// Two candidates scoring 60 and 55 -> margin 5 < 15 -> create_new with confidence=0.3
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:        int64(51),
				CurrentIP: "10.0.0.99",
				Hostname:  "server",
				Ports:     []string{"tcp/80/http", "tcp/443/https", "tcp/8080/http", "tcp/22/ssh"},
				LastSeen:  now.Add(-1 * time.Hour),
			},
			{
				ID:        int64(52),
				CurrentIP: "10.0.0.99",
				Hostname:  "server",
				LastSeen:  now.Add(-2 * time.Hour),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.99",
		Hostname:   "server",
		Ports:      []string{"tcp/80/http"},
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionCreateNew {
		t.Fatalf("expected create_new due to ambiguity margin, got %+v", dec)
	}
	if dec.Confidence != 0.3 {
		t.Errorf("expected confidence 0.3, got %f", dec.Confidence)
	}
}

func TestMatcher_ManagedBinding(t *testing.T) {
	// Managed agent A reports .40. Sweep sees .40 with no MAC -> bound to A outright
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	managedID := int64(60)

	store := &fakeCandidateStore{
		candidates: []Candidate{
			{
				ID:              managedID,
				CurrentIP:       "10.0.0.40",
				Managed:         true,
				AgentAlive:      true,
				AgentInterfaces: []string{"10.0.0.40", "172.17.0.1"},
				LastSeen:        now,
			},
			{
				ID:        int64(61),
				CurrentIP: "10.0.0.40",
				LastSeen:  now.Add(-1 * time.Hour),
			},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "10.0.0.40",
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != managedID {
		t.Fatalf("expected managed bind to %d, got %+v", managedID, dec)
	}
	if dec.Reason != "agent_interface" {
		t.Errorf("expected reason agent_interface, got %s", dec.Reason)
	}
}

func TestMatcher_Determinism(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

	baseCandidates := []Candidate{
		{ID: 1, CurrentIP: "10.0.0.2", Hostname: "host-a", LastSeen: now.Add(-10 * time.Minute)},
		{ID: 2, CurrentIP: "10.0.0.3", Hostname: "host-b", LastSeen: now.Add(-20 * time.Minute)},
		{ID: 3, CurrentIP: "10.0.0.4", Hostname: "host-c", LastSeen: now.Add(-5 * time.Minute)},
		{ID: 4, CurrentIP: "10.0.0.5", Hostname: "host-d", LastSeen: now.Add(-30 * time.Minute)},
	}

	obs := Observation{
		IP:         "10.0.0.2",
		Hostname:   "host-a",
		ObservedAt: now,
	}

	store := &fakeCandidateStore{candidates: baseCandidates}
	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	expected, err := matcher.Resolve(context.Background(), obs)
	if err != nil {
		t.Fatalf("initial resolve failed: %v", err)
	}

	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		shuffled := make([]Candidate, len(baseCandidates))
		copy(shuffled, baseCandidates)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})

		store.candidates = shuffled
		got, err := matcher.Resolve(context.Background(), obs)
		if err != nil {
			t.Fatalf("iteration %d resolve failed: %v", i, err)
		}

		if got.Action != expected.Action || *got.DeviceID != *expected.DeviceID || got.Score != expected.Score {
			t.Fatalf("determinism failure on permutation %d: expected %+v, got %+v", i, expected, got)
		}
	}
}

func TestMatcher_FirstMACForIPOnlyDeviceBinds(t *testing.T) {
	// D was recorded without a MAC by an unprivileged sweep. The next sweep reads its MAC from
	// the ARP table: the observation must bind to D (30 IPLease + 20 IPOnlyLease) and not
	// create a second device for the same host.
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	dID := int64(300)
	store := &fakeCandidateStore{
		candidates: []Candidate{
			{ID: dID, CurrentIP: "192.168.0.1", LastSeen: now.Add(-5 * time.Minute), IdentityConfidence: 0.3},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "192.168.0.1",
		MAC:        "B0:A7:B9:22:8D:2C",
		Vendor:     "TP-Link Systems",
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != dID {
		t.Fatalf("expected bind to IP-only device %d, got %+v", dID, dec)
	}
}

func TestMatcher_ScanWithoutMACBindsDeviceOverEmptyStubs(t *testing.T) {
	// D holds .101 with a MAC. Two empty stubs from earlier unprivileged scans share the IP.
	// A vulnerability scan observation (no MAC, a hostname and open ports) must bind to D:
	// the stubs carry no evidence and must not make the match ambiguous.
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	dID := int64(5)
	store := &fakeCandidateStore{
		candidates: []Candidate{
			{ID: 2, CurrentIP: "192.168.0.101", LastSeen: now.Add(-10 * time.Minute)},
			{ID: dID, CurrentIP: "192.168.0.101", MAC: "80:0d:3f:4d:e9:68", LastSeen: now.Add(-1 * time.Minute)},
			{ID: 9, CurrentIP: "192.168.0.101", LastSeen: now.Add(-2 * time.Minute)},
		},
	}

	matcher := NewMatcher(store, DefaultWeights(), func() time.Time { return now })
	dec, err := matcher.Resolve(context.Background(), Observation{
		IP:         "192.168.0.101",
		Hostname:   "galaxy-tab",
		Ports:      []string{"tcp/8008/http"},
		ObservedAt: now,
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if dec.Action != ActionBind || dec.DeviceID == nil || *dec.DeviceID != dID {
		t.Fatalf("expected bind to device %d, got %+v", dID, dec)
	}
}
