package ingest

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

// Handler provides HTTP handlers for agent enrollment, telemetry ingestion, and agent management.
type Handler struct {
	cfg        *config.Config
	store      *storage.Storage
	dispatcher *Dispatcher
}

// NewHandler creates a new Handler instance.
func NewHandler(cfg *config.Config, store *storage.Storage, dispatcher *Dispatcher) *Handler {
	return &Handler{
		cfg:        cfg,
		store:      store,
		dispatcher: dispatcher,
	}
}

// HandleEnroll registers an agent or rotates the agent's authentication token.
func (h *Handler) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if h.cfg.EnrollToken == "" {
		writeError(w, http.StatusForbidden, "enrollment is disabled")
		return
	}

	var req model.AgentEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json request body")
		return
	}

	if req.AgentID == "" || req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "agent_id and hostname are required")
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.EnrollmentToken), []byte(h.cfg.EnrollToken)) != 1 {
		writeError(w, http.StatusForbidden, "invalid enrollment token")
		return
	}

	rawTokenBytes := make([]byte, 32)
	if _, err := rand.Read(rawTokenBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate agent token")
		return
	}
	rawToken := hex.EncodeToString(rawTokenBytes)
	tokenHash := sha256.Sum256([]byte(rawToken))

	if err := h.store.EnrollAgent(r.Context(), req.AgentID, req.Hostname, tokenHash[:]); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(model.AgentEnrollResponse{
		AgentToken: rawToken,
	})
}

// HandleTelemetry ingests a batch of agent telemetry events.
func (h *Handler) HandleTelemetry(w http.ResponseWriter, r *http.Request) {
	if h.dispatcher != nil && h.dispatcher.IsBacklogged(r.Context()) {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusTooManyRequests, "ingestion backlog exceeded")
		return
	}

	maxBody := h.cfg.IngestMaxBody
	if maxBody <= 0 {
		maxBody = 1048576
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	var reader io.Reader = r.Body
	isGzip := r.Header.Get("Content-Encoding") == "gzip"

	if isGzip {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid gzip payload")
			return
		}
		defer gz.Close()
		// Limit decompressed stream to 4 MiB + 1 to detect gzip bombs
		reader = io.LimitReader(gz, 4*1024*1024+1)
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "payload exceeds body limit")
			return
		}
		writeError(w, http.StatusBadRequest, "error reading request body")
		return
	}

	if isGzip && len(bodyBytes) > 4*1024*1024 {
		writeError(w, http.StatusRequestEntityTooLarge, "decompressed gzip payload exceeds 4 MiB limit")
		return
	}

	var batch model.TelemetryBatch
	if err := json.Unmarshal(bodyBytes, &batch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if len(batch.Events) > 1000 {
		writeError(w, http.StatusBadRequest, "batch exceeds maximum limit of 1000 events")
		return
	}

	now := time.Now().UTC()
	var validEvents []model.NormalizedEvent
	var rejectedCount int

	for i := range batch.Events {
		if err := ValidateEvent(&batch.Events[i], now); err != nil {
			rejectedCount++
		} else {
			norm := NormalizeEvent(batch.Agent.AgentID, batch.Agent.BootID, &batch.Events[i])
			validEvents = append(validEvents, norm)
		}
	}

	// 50% or more invalid events in a batch triggers 400 Bad Request
	if len(batch.Events) > 0 && rejectedCount*2 >= len(batch.Events) {
		writeError(w, http.StatusBadRequest, "batch rejected: 50% or more events are invalid")
		return
	}

	batchID, isDuplicate, err := h.store.IngestBatch(r.Context(), &batch, validEvents, rejectedCount)
	if err != nil {
		if errors.Is(err, storage.ErrAgentConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)

	if isDuplicate {
		_ = json.NewEncoder(w).Encode(model.TelemetryResponse{
			Duplicate: true,
			Accepted:  0,
			Rejected:  0,
		})
		return
	}

	if h.dispatcher != nil {
		h.dispatcher.Submit(batchID, validEvents)
	}

	_ = json.NewEncoder(w).Encode(model.TelemetryResponse{
		Accepted: len(validEvents),
		Rejected: rejectedCount,
	})
}

// HandleGetAgents lists all registered agents.
func (h *Handler) HandleGetAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := h.store.GetAgents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if agents == nil {
		agents = []model.AgentRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"count":  len(agents),
		"agents": agents,
	})
}

// HandleGetAgentByID retrieves a single agent by ID.
func (h *Handler) HandleGetAgentByID(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	agent, err := h.store.GetAgentByID(r.Context(), agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if agent == nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(agent)
}

// HandleDeleteAgent revokes an agent.
func (h *Handler) HandleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if err := h.store.RevokeAgent(r.Context(), agentID); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "revoked",
	})
}

// HandleGetAgentEvents queries historical agent events.
func (h *Handler) HandleGetAgentEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	agentID := q.Get("agent_id")
	eventType := q.Get("type")

	var from, to *time.Time
	if fromStr := q.Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = &t
		}
	}
	if toStr := q.Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = &t
		}
	}

	limit := 50
	if limitStr := q.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	events, err := h.store.GetAgentEvents(r.Context(), agentID, eventType, from, to, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []model.NormalizedEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"count":  len(events),
		"events": events,
	})
}
