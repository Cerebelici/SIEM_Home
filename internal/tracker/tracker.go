package tracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gr0gu/cerberus/internal/config"
)

// Storage abstracts persistent metadata retrieval.
type Storage interface {
	GetOrCreateClientID(ctx context.Context) (string, error)
}

// Payload represents the active users message structure.
type Payload struct {
	ClientID   string `json:"client_id"`
	AppVersion string `json:"app_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
}

// Tracker manages 24-hour periodic heartbeats to the active users endpoint.
type Tracker struct {
	cfg        *config.Config
	storage    Storage
	httpClient *http.Client
	clientID   string
	mu         sync.Mutex
}

// New constructs a new Tracker instance.
func New(cfg *config.Config, store Storage) *Tracker {
	return &Tracker{
		cfg:     cfg,
		storage: store,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SetHTTPClient allows overriding the HTTP client (useful for tests).
func (t *Tracker) SetHTTPClient(client *http.Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.httpClient = client
}

// GetClientID returns the cached, configured, stored, or newly generated persistent client ID.
func (t *Tracker) GetClientID(ctx context.Context) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.clientID != "" {
		return t.clientID
	}
	if t.cfg != nil && t.cfg.ClientID != "" {
		t.clientID = t.cfg.ClientID
		return t.clientID
	}
	if t.storage != nil {
		id, err := t.storage.GetOrCreateClientID(ctx)
		if err == nil && id != "" {
			t.clientID = id
			return t.clientID
		}
	}
	t.clientID = uuid.NewString()
	return t.clientID
}

// BuildPayload constructs the active users payload according to system details and configuration.
func (t *Tracker) BuildPayload(ctx context.Context) Payload {
	clientID := t.GetClientID(ctx)
	appVersion := "0.1.0"
	if t.cfg != nil && t.cfg.AppVersion != "" {
		appVersion = t.cfg.AppVersion
	}
	return Payload{
		ClientID:   clientID,
		AppVersion: appVersion,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}
}

// Send dispatches a single active users message to ActiveUsersHost.
func (t *Tracker) Send(ctx context.Context) error {
	if t.cfg == nil {
		return fmt.Errorf("tracker config is nil")
	}
	if !t.cfg.EnableTracking {
		log.Println("[Tracker] Tracking is disabled via configuration.")
		return nil
	}
	if strings.TrimSpace(t.cfg.ActiveUsersHost) == "" {
		log.Println("[Tracker] ActiveUsersHost endpoint is not configured; skipping heartbeat.")
		return nil
	}

	payload := t.BuildPayload(ctx)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling tracking payload: %w", err)
	}

	rawURL := strings.TrimSpace(t.cfg.ActiveUsersHost)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building tracking request for %s: %w", rawURL, err)
	}

	req.Header.Set("Content-Type", "application/json")
	if t.cfg.TrackingKey != "" {
		req.Header.Set("X-Tracking-Key", t.cfg.TrackingKey)
		req.Header.Set("Tracking-Key", t.cfg.TrackingKey)
		req.Header.Set("X-API-Key", t.cfg.TrackingKey)
		req.Header.Set("Authorization", "Bearer "+t.cfg.TrackingKey)
		req.Header.Set("Key", t.cfg.TrackingKey)
	}

	t.mu.Lock()
	client := t.httpClient
	t.mu.Unlock()

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("dispatching tracking payload to %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("tracking endpoint %s responded with status %d", rawURL, resp.StatusCode)
	}

	return nil
}

// Start begins the 24-hour periodic loop, sending an initial heartbeat upon start.
func (t *Tracker) Start(ctx context.Context, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	if t.cfg == nil || !t.cfg.EnableTracking || strings.TrimSpace(t.cfg.ActiveUsersHost) == "" {
		log.Println("[Tracker] Active users tracking is inactive (disabled or empty host).")
		return
	}

	interval := 24 * time.Hour
	if t.cfg.TrackingInterval > 0 {
		interval = t.cfg.TrackingInterval
	}

	log.Printf("[Tracker] Starting active users reporter (interval: %v, endpoint: %s)", interval, t.cfg.ActiveUsersHost)

	// Send initial report upon startup
	if err := t.Send(ctx); err != nil {
		log.Printf("[Tracker] Warning: initial active users ping failed: %v", err)
	} else {
		log.Printf("[Tracker] Initial active users ping delivered successfully.")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Tracker] Active users reporter shutting down.")
			return
		case <-ticker.C:
			if err := t.Send(ctx); err != nil {
				log.Printf("[Tracker] Warning: periodic active users ping failed: %v", err)
			} else {
				log.Printf("[Tracker] Periodic active users ping delivered successfully.")
			}
		}
	}
}
