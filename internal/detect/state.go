package detect

import (
	"container/list"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

const (
	defaultProcLRUCapacity = 50000
	defaultProcTTL         = 10 * time.Minute
	connectRingSize        = 8
)

// ConnectRecord tracks an outbound network connection.
type ConnectRecord struct {
	DstIP   netip.Addr
	DstPort uint16
	TS      time.Time
}

// Proc represents an observed active or recent process on a monitored host.
type Proc struct {
	PID         uint32
	PPID        uint32
	Comm        string
	Image       string
	ExecTS      time.Time
	MemfdTS     time.Time
	Connects    []ConnectRecord
	DstFanout   map[string]time.Time // key: "dst_ip:dst_port" -> timestamp
	LastUpdated time.Time
}

// RecordConnect adds a connection to the ring buffer and the fan-out tracking map.
func (p *Proc) RecordConnect(ip netip.Addr, port uint16, ts time.Time) {
	if len(p.Connects) >= connectRingSize {
		p.Connects = p.Connects[1:]
	}
	p.Connects = append(p.Connects, ConnectRecord{DstIP: ip, DstPort: port, TS: ts})

	if p.DstFanout == nil {
		p.DstFanout = make(map[string]time.Time)
	}

	key := fmt.Sprintf("%s:%d", ip.String(), port)
	p.DstFanout[key] = ts

	// Prune fanout older than 10 seconds
	cutoff := ts.Add(-10 * time.Second)
	for k, t := range p.DstFanout {
		if t.Before(cutoff) {
			delete(p.DstFanout, k)
		}
	}
}

// OutboundFanoutCount returns the count of distinct destinations contacted in the last 10s.
func (p *Proc) OutboundFanoutCount(now time.Time) int {
	cutoff := now.Add(-10 * time.Second)
	count := 0
	for _, t := range p.DstFanout {
		if !t.Before(cutoff) {
			count++
		}
	}
	return count
}

type lruEntry struct {
	pid  uint32
	proc *Proc
	exp  time.Time
}

// ProcLRU is a bounded, TTL-expiring cache for process metadata.
type ProcLRU struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	items    map[uint32]*list.Element
	evict    *list.List
}

// NewProcLRU creates a new LRU cache with the specified capacity and TTL.
func NewProcLRU(capacity int, ttl time.Duration) *ProcLRU {
	if capacity <= 0 {
		capacity = defaultProcLRUCapacity
	}
	if ttl <= 0 {
		ttl = defaultProcTTL
	}
	return &ProcLRU{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[uint32]*list.Element),
		evict:    list.New(),
	}
}

// Get returns the process for a given PID if present and not expired.
func (c *ProcLRU) Get(pid uint32, now time.Time) *Proc {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[pid]
	if !exists {
		return nil
	}

	entry := elem.Value.(*lruEntry)
	if now.After(entry.exp) {
		c.removeElement(elem)
		return nil
	}

	c.evict.MoveToFront(elem)
	return entry.proc
}

// Put adds or updates a process in the LRU cache.
func (c *ProcLRU) Put(proc *Proc, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.items[proc.PID]; exists {
		c.evict.MoveToFront(elem)
		entry := elem.Value.(*lruEntry)
		entry.proc = proc
		entry.exp = now.Add(c.ttl)
		return
	}

	// Evict oldest if capacity exceeded
	for c.evict.Len() >= c.capacity {
		oldest := c.evict.Back()
		if oldest != nil {
			c.removeElement(oldest)
		}
	}

	entry := &lruEntry{
		pid:  proc.PID,
		proc: proc,
		exp:  now.Add(c.ttl),
	}
	elem := c.evict.PushFront(entry)
	c.items[proc.PID] = elem
}

func (c *ProcLRU) removeElement(elem *list.Element) {
	c.evict.Remove(elem)
	entry := elem.Value.(*lruEntry)
	delete(c.items, entry.pid)
}

// Clear flushes all entries from the LRU.
func (c *ProcLRU) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[uint32]*list.Element)
	c.evict.Init()
}

// HostState encapsulates the process hierarchy and state for a single monitored agent.
type HostState struct {
	mu      sync.RWMutex
	AgentID string
	BootID  string
	Procs   *ProcLRU
}

// NewHostState initializes a new HostState.
func NewHostState(agentID string) *HostState {
	return &HostState{
		AgentID: agentID,
		Procs:   NewProcLRU(defaultProcLRUCapacity, defaultProcTTL),
	}
}

// Reset clears the process table when a reboot (boot_id change) is detected.
func (st *HostState) Reset(newBootID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.BootID = newBootID
	st.Procs.Clear()
}

// UpdateState processes an event to maintain process trees and execution timelines.
func (st *HostState) UpdateState(ev *model.NormalizedEvent) {
	st.mu.Lock()
	defer st.mu.Unlock()

	// 1. Detect boot ID transition
	if ev.BootID != "" {
		if st.BootID != "" && st.BootID != ev.BootID {
			st.BootID = ev.BootID
			st.Procs.Clear()
		} else if st.BootID == "" {
			st.BootID = ev.BootID
		}
	}

	now := ev.TS
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// 2. State maintenance per event type
	switch ev.Type {
	case "EXEC":
		proc := st.Procs.Get(ev.PID, now)
		if proc == nil {
			proc = &Proc{
				PID:       ev.PID,
				DstFanout: make(map[string]time.Time),
			}
		}
		proc.PPID = ev.PPID
		proc.Comm = ev.Comm
		proc.Image = ev.Image
		proc.ExecTS = ev.TS
		proc.LastUpdated = now
		st.Procs.Put(proc, now)

	case "MEMFD_CREATE":
		proc := st.Procs.Get(ev.PID, now)
		if proc == nil {
			proc = &Proc{
				PID:       ev.PID,
				PPID:      ev.PPID,
				Comm:      ev.Comm,
				DstFanout: make(map[string]time.Time),
			}
		}
		proc.MemfdTS = ev.TS
		proc.LastUpdated = now
		st.Procs.Put(proc, now)

	case "CONNECT":
		proc := st.Procs.Get(ev.PID, now)
		if proc == nil {
			proc = &Proc{
				PID:       ev.PID,
				PPID:      ev.PPID,
				Comm:      ev.Comm,
				Image:     ev.Image,
				DstFanout: make(map[string]time.Time),
			}
		}
		proc.RecordConnect(ev.DstIP, ev.DstPort, ev.TS)
		proc.LastUpdated = now
		st.Procs.Put(proc, now)
	}
}

// GetProc retrieves the process for a PID.
func (st *HostState) GetProc(pid uint32, now time.Time) *Proc {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.Procs.Get(pid, now)
}

// ResolvePIDRoot finds the highest ancestor process whose image is NOT a shell.
// Fallback: returns the pid itself.
func (st *HostState) ResolvePIDRoot(pid uint32, now time.Time, policy *Policy) uint32 {
	st.mu.RLock()
	defer st.mu.RUnlock()

	curr := pid
	highestNonShell := uint32(0)

	for depth := 0; depth < 32 && curr > 1; depth++ {
		proc := st.Procs.Get(curr, now)
		if proc == nil {
			break
		}
		if !policy.IsShell(proc.Image, proc.Comm) {
			highestNonShell = curr
		}
		if proc.PPID == 0 || proc.PPID == curr {
			break
		}
		curr = proc.PPID
	}

	if highestNonShell != 0 {
		return highestNonShell
	}
	return pid
}
