package ingest_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/ingest"
	"github.com/gr0gu/cerberus/internal/model"
)

// FuzzDecodeBatch validates that arbitrary input bytes never cause a panic during decoding, validation, or normalization.
func FuzzDecodeBatch(f *testing.F) {
	// Seed corpus with valid and invalid batches
	f.Add([]byte(`{"schema_version":1,"agent":{"agent_id":"a1","boot_id":"b1","hostname":"h1"},"batch":{"seq":1,"sent_at":"2026-10-12T20:00:00Z"},"events":[{"type":"EXEC","comm":"ls","data":{"filename":"/bin/ls"}}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"events":[null, 123, "string"]}`))
	f.Add([]byte(`{"schema_version":99999999,"events":[]}`))
	f.Add([]byte(`{"events":[{"type":"CONNECT","data":{"family":"inet","dst_ip":"999.999.999.999","dst_port":99999}}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var batch model.TelemetryBatch
		if err := json.Unmarshal(data, &batch); err != nil {
			return
		}

		now := time.Now().UTC()
		for i := range batch.Events {
			_ = ingest.ValidateEvent(&batch.Events[i], now)
			_ = ingest.NormalizeEvent(batch.Agent.AgentID, batch.Agent.BootID, &batch.Events[i])
		}
	})
}
