package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// handleGetDevices returns all tracked devices, with optional ?status=up|down filter.
func (s *Server) handleGetDevices(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")

	devices, err := s.storage.GetDevices(r.Context(), statusFilter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if devices == nil {
		devices = []model.Device{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(devices),
		"devices": devices,
	})
}

// handleGetDeviceByID returns detailed device info including open services and CVEs.
func (s *Server) handleGetDeviceByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	device, err := s.storage.GetDeviceByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if device == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("device %d not found", id)})
		return
	}

	writeJSON(w, http.StatusOK, device)
}

// handleGetServices returns all services detected across the entire network.
func (s *Server) handleGetServices(w http.ResponseWriter, r *http.Request) {
	services, err := s.storage.GetAllServices(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if services == nil {
		services = []model.Service{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":    len(services),
		"services": services,
	})
}

// handleGetVulnerabilities returns all detected vulnerabilities, with optional ?severity=CRITICAL filter.
func (s *Server) handleGetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")

	vulns, err := s.storage.GetAllVulnerabilities(r.Context(), severity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if vulns == nil {
		vulns = []model.Vulnerability{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":           len(vulns),
		"vulnerabilities": vulns,
	})
}

// handleGetScans returns recent scan execution history.
func (s *Server) handleGetScans(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	scans, err := s.storage.GetRecentScans(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if scans == nil {
		scans = []model.ScanLog{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(scans),
		"scans": scans,
	})
}

// handleTriggerDiscovery launches an immediate network discovery scan.
func (s *Server) handleTriggerDiscovery(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ScanTimeout)
		defer cancel()
		_ = s.scheduler.TriggerDiscovery(ctx)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{
		"message": "Discovery scan initiated in background",
		"status":  "running",
	})
}

// handleTriggerVuln launches an immediate vulnerability scan across active devices.
func (s *Server) handleTriggerVuln(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ScanTimeout)
		defer cancel()
		_ = s.scheduler.TriggerVulnerabilityScan(ctx)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{
		"message": "Vulnerability audit initiated in background",
		"status":  "running",
	})
}

// handleGetStatus returns system health, uptime, counts, and scheduler state.
func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	totalDevs, activeDevs, totalSvcs, totalVulns, err := s.storage.GetCounts(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	uptimeDuration := time.Since(s.startTime)
	discNext, vulnNext, discRunning, vulnRunning := s.scheduler.GetNextRuns()

	caps := s.capabilities
	if caps == nil {
		caps = &model.Capabilities{
			NmapPath:      s.cfg.NmapPath,
			EffectiveMode: "unprivileged",
		}
	}

	status := model.SystemStatus{
		Uptime:               uptimeDuration.Round(time.Second).String(),
		UptimeSeconds:        int64(uptimeDuration.Seconds()),
		TotalDevices:         totalDevs,
		ActiveDevices:        activeDevs,
		TotalServices:        totalSvcs,
		TotalVulnerabilities: totalVulns,
		DiscoveryNextRun:     discNext,
		VulnNextRun:          vulnNext,
		IsDiscoveryRunning:   discRunning,
		IsVulnRunning:        vulnRunning,
		Capabilities:         caps,
	}

	if s.engine != nil {
		status.IngestEventsTotal = s.engine.IngestEventsTotal()
		status.DetectLagMsP95 = s.engine.DetectLagMsP95()
		status.IncidentsOpen = s.engine.OpenIncidentsCount(r.Context())
	}

	writeJSON(w, http.StatusOK, status)
}

// handleExportJSON returns the full network sentinel dataset formatted as JSON.
func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	data, err := s.storage.ExportAllData(r.Context(), s.cfg.NetworkCIDR)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"cerberus-export-%s.json\"", time.Now().Format("20060102-150405")))
	writeJSON(w, http.StatusOK, data)
}

// handleGetTimeline returns scan ticks and device activity periods for frontend timeline rendering.
func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	to := now

	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if parsedTo, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = parsedTo.UTC()
		}
	}

	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if parsedFrom, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = parsedFrom.UTC()
		} else if dur, err := time.ParseDuration(fromStr); err == nil {
			from = to.Add(-dur)
		}
	}

	statusFilter := r.URL.Query().Get("status")
	vulnOnlyStr := r.URL.Query().Get("vulnerable_only")
	if vulnOnlyStr == "" {
		vulnOnlyStr = r.URL.Query().Get("vulnerable")
	}
	vulnerableOnly := vulnOnlyStr == "true" || vulnOnlyStr == "1"

	timeline, err := s.storage.GetTimeline(r.Context(), from, to, statusFilter, vulnerableOnly)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, timeline)
}

// handleGetIncidents retrieves security incidents filtered by query parameters.
func (s *Server) handleGetIncidents(w http.ResponseWriter, r *http.Request) {
	filter := model.IncidentFilter{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
	}

	if devIDStr := r.URL.Query().Get("device_id"); devIDStr != "" {
		if id, err := strconv.ParseInt(devIDStr, 10, 64); err == nil {
			filter.DeviceID = &id
		}
	}
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			tUTC := t.UTC()
			filter.From = &tUTC
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			tUTC := t.UTC()
			filter.To = &tUTC
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if lim, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = lim
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if off, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = off
		}
	}

	incidents, err := s.storage.GetIncidents(r.Context(), filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, incidents)
}

// handleGetIncidentByID retrieves details for a single incident, including evidence event records.
func (s *Server) handleGetIncidentByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			idStr = parts[2]
		}
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid incident id"})
		return
	}

	inc, err := s.storage.GetIncidentByID(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, inc)
}

// handlePatchIncident updates an incident's triage status (open, acknowledged, closed).
func (s *Server) handlePatchIncident(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			idStr = parts[2]
		}
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid incident id"})
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	req.Status = strings.ToLower(strings.TrimSpace(req.Status))
	if req.Status != "open" && req.Status != "acknowledged" && req.Status != "closed" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of: open, acknowledged, closed"})
		return
	}

	if err := s.storage.UpdateIncidentStatus(r.Context(), id, req.Status); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	inc, err := s.storage.GetIncidentByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "status": req.Status})
		return
	}

	writeJSON(w, http.StatusOK, inc)
}
