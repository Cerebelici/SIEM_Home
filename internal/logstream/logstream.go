// Package logstream keeps the recent lines of the process log in memory and streams new
// lines to listeners, so the UI can show the real daemon log.
package logstream

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Entry is one line of the daemon log.
type Entry struct {
	Seq       int64     `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
}

// Log levels derived from the text of a line.
const (
	LevelError = "ERROR"
	LevelWarn  = "WARN"
	LevelInfo  = "INFO"
)

// Buffer is an io.Writer for the standard logger. It keeps the last lines and notifies
// listeners about each new line. It is safe for concurrent use.
type Buffer struct {
	mu        sync.Mutex
	entries   []Entry
	max       int
	seq       int64
	partial   []byte
	listeners map[int]func(Entry)
	nextID    int
}

// New returns a Buffer that keeps at most max lines.
func New(max int) *Buffer {
	if max <= 0 {
		max = 1000
	}
	return &Buffer{max: max, listeners: make(map[int]func(Entry))}
}

// stdPrefix matches the date and time that log.LstdFlags writes before each line.
var stdPrefix = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? `)

// Write splits p into lines and records each complete line.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.partial = append(b.partial, p...)
	var added []Entry
	for {
		i := bytes.IndexByte(b.partial, '\n')
		if i < 0 {
			break
		}
		line := string(b.partial[:i])
		b.partial = b.partial[i+1:]
		if entry, ok := b.record(line); ok {
			added = append(added, entry)
		}
	}
	listeners := make([]func(Entry), 0, len(b.listeners))
	for _, fn := range b.listeners {
		listeners = append(listeners, fn)
	}
	b.mu.Unlock()

	for _, entry := range added {
		for _, fn := range listeners {
			fn(entry)
		}
	}
	return len(p), nil
}

// record parses and stores one line. The caller holds b.mu.
func (b *Buffer) record(line string) (Entry, bool) {
	line = strings.TrimSpace(stdPrefix.ReplaceAllString(line, ""))
	if line == "" {
		return Entry{}, false
	}
	source := "System"
	message := line
	if strings.HasPrefix(line, "[") {
		if end := strings.Index(line, "]"); end > 1 {
			source = line[1:end]
			message = strings.TrimSpace(line[end+1:])
		}
	}

	b.seq++
	entry := Entry{
		Seq:       b.seq,
		Timestamp: time.Now().UTC(),
		Level:     levelOf(message),
		Source:    source,
		Message:   message,
	}
	b.entries = append(b.entries, entry)
	if len(b.entries) > b.max {
		b.entries = append([]Entry(nil), b.entries[len(b.entries)-b.max:]...)
	}
	return entry, true
}

// levelOf derives a level from the words of a message. The daemon logs with the standard
// logger, which has no levels, but its messages name errors and warnings consistently.
func levelOf(message string) string {
	lower := strings.ToLower(message)
	for _, word := range []string{"error", "failed", "fatal", "panic"} {
		if strings.Contains(lower, word) {
			return LevelError
		}
	}
	for _, word := range []string{"warning", "skipping", "dropping", "blocks", "blocked"} {
		if strings.Contains(lower, word) {
			return LevelWarn
		}
	}
	return LevelInfo
}

// Entries returns a copy of the kept lines, oldest first.
func (b *Buffer) Entries() []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Entry(nil), b.entries...)
}

// Subscribe calls fn for every new line until the returned function is called.
func (b *Buffer) Subscribe(fn func(Entry)) (unsubscribe func()) {
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.listeners[id] = fn
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		delete(b.listeners, id)
		b.mu.Unlock()
	}
}
