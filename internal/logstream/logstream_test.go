package logstream

import (
	"fmt"
	"log"
	"testing"
)

func TestBuffer_ParsesStandardLoggerLines(t *testing.T) {
	buf := New(10)
	logger := log.New(buf, "", log.LstdFlags)

	var streamed []Entry
	unsubscribe := buf.Subscribe(func(e Entry) { streamed = append(streamed, e) })

	logger.Printf("[Discovery] Completed. Discovered 3 live hosts (0 new) in 34000ms")
	logger.Printf("[Discovery] Scan error: discovery scan failed: exit status 1")
	logger.Printf("[Daemon] Preflight inspection warning: nmap not found")
	logger.Printf("plain line without a source")

	entries := buf.Entries()
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	want := []struct{ level, source, message string }{
		{LevelInfo, "Discovery", "Completed. Discovered 3 live hosts (0 new) in 34000ms"},
		{LevelError, "Discovery", "Scan error: discovery scan failed: exit status 1"},
		{LevelWarn, "Daemon", "Preflight inspection warning: nmap not found"},
		{LevelInfo, "System", "plain line without a source"},
	}
	for i, w := range want {
		e := entries[i]
		if e.Level != w.level || e.Source != w.source || e.Message != w.message {
			t.Errorf("entry %d = {%s %s %q}, want {%s %s %q}", i, e.Level, e.Source, e.Message, w.level, w.source, w.message)
		}
		if e.Seq != int64(i+1) {
			t.Errorf("entry %d seq = %d, want %d", i, e.Seq, i+1)
		}
	}
	if len(streamed) != 4 {
		t.Errorf("expected 4 streamed entries, got %d", len(streamed))
	}

	unsubscribe()
	logger.Printf("[Daemon] after unsubscribe")
	if len(streamed) != 4 {
		t.Errorf("listener called after unsubscribe")
	}
}

func TestBuffer_KeepsOnlyLastLinesAndJoinsPartialWrites(t *testing.T) {
	buf := New(3)
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(buf, "[Test] line %d\n", i)
	}
	_, _ = buf.Write([]byte("[Test] split "))
	_, _ = buf.Write([]byte("line\n"))

	entries := buf.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Message != "line 4" || entries[2].Message != "split line" {
		t.Errorf("unexpected entries: %+v", entries)
	}
	if entries[2].Seq != 6 {
		t.Errorf("expected seq 6 for the last entry, got %d", entries[2].Seq)
	}
}
