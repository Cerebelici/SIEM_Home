package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

var (
	ErrInvalidEventType     = errors.New("unsupported or empty event type")
	ErrMissingRequiredField = errors.New("missing or invalid required data field")
	ErrStringTooLong        = errors.New("string field exceeds 512 bytes")
)

// ValidateEvent checks a raw event against type-specific schemas, constraints, and time bounds.
func ValidateEvent(ev *model.RawEvent, now time.Time) error {
	if ev.Type == "" {
		return ErrInvalidEventType
	}

	// 1. Timestamp validation (within +-24h of server time; clamp if outside)
	if ev.TS.IsZero() {
		ev.TS = now
	} else {
		diff := ev.TS.Sub(now)
		if diff > 24*time.Hour {
			ev.TS = now.Add(24 * time.Hour)
		} else if diff < -24*time.Hour {
			ev.TS = now.Add(-24 * time.Hour)
		}
	}

	// 2. Validate strings: UTF-8 sanity and max 512 bytes
	ev.Comm = sanitizeString(ev.Comm, 512)

	// 3. Type-specific data validation
	if len(ev.Data) == 0 {
		return fmt.Errorf("%w: empty data payload", ErrMissingRequiredField)
	}

	var dataMap map[string]any
	if err := json.Unmarshal(ev.Data, &dataMap); err != nil {
		return fmt.Errorf("%w: invalid JSON in data", ErrMissingRequiredField)
	}

	switch ev.Type {
	case "EXEC":
		fn, ok := dataMap["filename"].(string)
		if !ok || fn == "" {
			return fmt.Errorf("%w: EXEC requires non-empty 'filename'", ErrMissingRequiredField)
		}
		if len(fn) > 512 {
			return ErrStringTooLong
		}

	case "CONNECT":
		family, _ := dataMap["family"].(string)
		if family != "inet" && family != "inet6" {
			return fmt.Errorf("%w: CONNECT requires family 'inet' or 'inet6'", ErrMissingRequiredField)
		}
		dstIPStr, _ := dataMap["dst_ip"].(string)
		if dstIPStr == "" {
			return fmt.Errorf("%w: CONNECT requires 'dst_ip'", ErrMissingRequiredField)
		}
		if _, err := netip.ParseAddr(dstIPStr); err != nil {
			return fmt.Errorf("%w: invalid 'dst_ip' %q", ErrMissingRequiredField, dstIPStr)
		}
		portFloat, ok := dataMap["dst_port"].(float64)
		if !ok || portFloat < 0 || portFloat > 65535 {
			return fmt.Errorf("%w: CONNECT requires dst_port between 0 and 65535", ErrMissingRequiredField)
		}

	case "BASH_READLINE":
		cmd, ok := dataMap["command"].(string)
		if !ok || cmd == "" {
			return fmt.Errorf("%w: BASH_READLINE requires non-empty 'command'", ErrMissingRequiredField)
		}

	case "PROC_INJECTION":
		method, _ := dataMap["method"].(string)
		if method != "process_vm_writev" && method != "ptrace" {
			return fmt.Errorf("%w: PROC_INJECTION requires method 'process_vm_writev' or 'ptrace'", ErrMissingRequiredField)
		}
		targetPID, ok := dataMap["target_pid"].(float64)
		if !ok || targetPID <= 0 {
			return fmt.Errorf("%w: PROC_INJECTION requires target_pid > 0", ErrMissingRequiredField)
		}

	case "FILE_TAMPER":
		path, ok := dataMap["path"].(string)
		if !ok || path == "" {
			return fmt.Errorf("%w: FILE_TAMPER requires non-empty 'path'", ErrMissingRequiredField)
		}
		if len(path) > 512 {
			return ErrStringTooLong
		}

	case "PRIV_ESC":
		_, ok1 := dataMap["old_uid"].(float64)
		_, ok2 := dataMap["target_uid"].(float64)
		if !ok1 || !ok2 {
			return fmt.Errorf("%w: PRIV_ESC requires numeric 'old_uid' and 'target_uid'", ErrMissingRequiredField)
		}

	case "KERNEL_MODULE":
		_, ok := dataMap["args"].(string)
		if !ok {
			return fmt.Errorf("%w: KERNEL_MODULE requires 'args' string", ErrMissingRequiredField)
		}

	case "MEMFD_CREATE":
		name, ok := dataMap["name"].(string)
		if !ok || name == "" {
			return fmt.Errorf("%w: MEMFD_CREATE requires non-empty 'name'", ErrMissingRequiredField)
		}
		if len(name) > 512 {
			return ErrStringTooLong
		}

	default:
		return fmt.Errorf("%w: %s", ErrInvalidEventType, ev.Type)
	}

	return nil
}

func sanitizeString(s string, maxLen int) string {
	s = strings.ToValidUTF8(s, "")
	if maxLen > 0 && len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}
