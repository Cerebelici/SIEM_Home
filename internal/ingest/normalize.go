package ingest

import (
	"encoding/json"
	"net/netip"

	"github.com/gr0gu/cerberus/internal/model"
)

// NormalizeEvent transforms a validated RawEvent into a NormalizedEvent ready for storage and detection.
func NormalizeEvent(agentID, bootID string, ev *model.RawEvent) model.NormalizedEvent {
	norm := model.NormalizedEvent{
		AgentID:  agentID,
		BootID:   bootID,
		Type:     ev.Type,
		TS:       ev.TS,
		PID:      ev.PID,
		PPID:     ev.PPID,
		UID:      ev.UID,
		GID:      ev.GID,
		Comm:     ev.Comm,
		DataJSON: string(ev.Data),
	}

	if ev.AgentAssessment != nil {
		norm.AgentRule = ev.AgentAssessment.Rule
		norm.AgentSeverity = ev.AgentAssessment.Severity
	}

	var dataMap map[string]any
	_ = json.Unmarshal(ev.Data, &dataMap)

	switch ev.Type {
	case "EXEC":
		norm.Category = "process"
		norm.Action = "exec"
		if fn, ok := dataMap["filename"].(string); ok {
			norm.Image = fn
		}

	case "CONNECT":
		norm.Category = "network"
		norm.Action = "connect"
		if ipStr, ok := dataMap["dst_ip"].(string); ok {
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				norm.DstIP = addr
			}
		}
		if port, ok := dataMap["dst_port"].(float64); ok {
			norm.DstPort = uint16(port)
		}

	case "BASH_READLINE":
		norm.Category = "shell"
		norm.Action = "readline"
		if cmd, ok := dataMap["command"].(string); ok {
			norm.Command = cmd
		}

	case "PROC_INJECTION":
		norm.Category = "process"
		norm.Action = "injection"
		if targetPID, ok := dataMap["target_pid"].(float64); ok {
			norm.TargetPID = uint32(targetPID)
		}

	case "FILE_TAMPER":
		norm.Category = "file"
		norm.Action = "tamper"
		if p, ok := dataMap["path"].(string); ok {
			norm.Path = p
		}

	case "PRIV_ESC":
		norm.Category = "privilege"
		norm.Action = "escalation"
		if oldUID, ok := dataMap["old_uid"].(float64); ok {
			norm.OldUID = uint32(oldUID)
		}
		if targetUID, ok := dataMap["target_uid"].(float64); ok {
			norm.TargetUID = uint32(targetUID)
		}

	case "KERNEL_MODULE":
		norm.Category = "kernel"
		norm.Action = "module"
		if args, ok := dataMap["args"].(string); ok {
			norm.Command = args
		}

	case "MEMFD_CREATE":
		norm.Category = "process"
		norm.Action = "memfd"
		if name, ok := dataMap["name"].(string); ok {
			norm.Path = name
		}

	default:
		norm.Category = "unknown"
		norm.Action = "unknown"
	}

	return norm
}
