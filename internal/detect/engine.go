package detect

import (
	"context"
	"crypto/sha1"
	"fmt"
	"hash/fnv"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

const (
	reservoirSize   = 2048
	dedupeWindow    = 5 * time.Minute
	shardQueueDepth = 64
)

// EngineMetrics maintains live performance telemetry for status reporting.
type EngineMetrics struct {
	mu           sync.Mutex
	eventsTotal  atomic.Uint64
	reservoir    []float64
	reservoirCap int
	sampleCount  uint64
	rng          *rand.Rand
}

func newEngineMetrics() *EngineMetrics {
	return &EngineMetrics{
		reservoir:    make([]float64, 0, reservoirSize),
		reservoirCap: reservoirSize,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (m *EngineMetrics) RecordLag(lagMs float64) {
	if lagMs < 0 {
		lagMs = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sampleCount++
	if len(m.reservoir) < m.reservoirCap {
		m.reservoir = append(m.reservoir, lagMs)
	} else {
		// Reservoir sampling (Algorithm R)
		j := m.rng.Int63n(int64(m.sampleCount))
		if j < int64(m.reservoirCap) {
			m.reservoir[j] = lagMs
		}
	}
}

func (m *EngineMetrics) P95LagMs() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	n := len(m.reservoir)
	if n == 0 {
		return 0.0
	}

	sorted := make([]float64, n)
	copy(sorted, m.reservoir)
	sort.Float64s(sorted)

	idx := int(float64(n) * 0.95)
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

type batchTask struct {
	batchID int64
	events  []model.NormalizedEvent
}

type engineShard struct {
	ch     chan batchTask
	states map[string]*HostState
}

// Engine evaluates ingested events against threat detection rules in real-time.
type Engine struct {
	rules   []Rule
	policy  *Policy
	store   storage.IncidentStore
	clock   func() time.Time
	metrics *EngineMetrics
	shards  []*engineShard
	numSh   int
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

// Option configures an Engine instance.
type Option func(*Engine)

// WithClock sets a custom clock function (useful for reproducible unit testing).
func WithClock(clock func() time.Time) Option {
	return func(e *Engine) {
		e.clock = clock
	}
}

// WithPolicy sets a custom detection policy.
func WithPolicy(policy *Policy) Option {
	return func(e *Engine) {
		e.policy = policy
	}
}

// WithRules overrides the active detection rules.
func WithRules(rules []Rule) Option {
	return func(e *Engine) {
		e.rules = rules
	}
}

// WithNumShards configures the number of worker shards.
func WithNumShards(numShards int) Option {
	return func(e *Engine) {
		if numShards > 0 {
			e.numSh = numShards
		}
	}
}

// NewEngine initializes a detection engine with default rules R001–R010.
func NewEngine(store storage.IncidentStore, opts ...Option) *Engine {
	e := &Engine{
		store:   store,
		clock:   func() time.Time { return time.Now().UTC() },
		policy:  LoadPolicy(),
		metrics: newEngineMetrics(),
		numSh:   runtime.GOMAXPROCS(0),
		rules: []Rule{
			&RuleR001{},
			&RuleR002{},
			&RuleR003{},
			&RuleR004{},
			&RuleR005{},
			&RuleR006{},
			&RuleR007{},
			&RuleR008{},
			&RuleR009{},
			&RuleR010{},
		},
	}

	for _, opt := range opts {
		opt(e)
	}

	e.shards = make([]*engineShard, e.numSh)
	for i := 0; i < e.numSh; i++ {
		e.shards[i] = &engineShard{
			ch:     make(chan batchTask, shardQueueDepth),
			states: make(map[string]*HostState),
		}
	}

	return e
}

// Start launches the background worker goroutines.
func (e *Engine) Start(ctx context.Context) {
	e.ctx, e.cancel = context.WithCancel(ctx)
	for i := 0; i < e.numSh; i++ {
		e.wg.Add(1)
		go e.runShard(e.shards[i])
	}
}

func (e *Engine) runShard(s *engineShard) {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			// Drain remaining work in channel
			for {
				select {
				case task := <-s.ch:
					e.processShardTask(s, task)
				default:
					return
				}
			}
		case task := <-s.ch:
			e.processShardTask(s, task)
		}
	}
}

func (e *Engine) processShardTask(s *engineShard, task batchTask) {
	for i := range task.events {
		ev := &task.events[i]
		e.metrics.eventsTotal.Add(1)

		now := e.clock()
		lagMs := float64(now.Sub(ev.TS).Milliseconds())
		e.metrics.RecordLag(lagMs)

		st, exists := s.states[ev.AgentID]
		if !exists {
			st = NewHostState(ev.AgentID)
			s.states[ev.AgentID] = st
		}

		// 1. Maintain process hierarchy and timeline state
		st.UpdateState(ev)

		// 2. Evaluate rules
		for _, r := range e.rules {
			findings := r.Evaluate(ev, st, e.policy)
			for _, f := range findings {
				e.handleFinding(ev, st, f)
			}
		}
	}
}

func (e *Engine) handleFinding(ev *model.NormalizedEvent, st *HostState, f Finding) {
	if e.store == nil {
		return
	}

	// Calculate deterministic dedupe key: sha1(agent_id|rule_id|pid_root)
	rawDedupe := fmt.Sprintf("%s|%s|%d", ev.AgentID, f.RuleID, f.PIDRoot)
	dedupeKey := fmt.Sprintf("%x", sha1.Sum([]byte(rawDedupe)))

	inc := &model.Incident{
		DeviceID:         ev.DeviceID,
		AgentID:          ev.AgentID,
		RuleID:           f.RuleID,
		RulesetVersion:   f.RulesetVersion,
		Title:            f.Title,
		Severity:         f.Severity,
		Score:            f.Score,
		MitreTactic:      f.MitreTactic,
		MitreTechnique:   f.MitreTechnique,
		PIDRoot:          f.PIDRoot,
		DedupeKey:        dedupeKey,
		FirstSeenAt:      ev.TS,
		LastSeenAt:       ev.TS,
		HitCount:         1,
		EvidenceEventIDs: f.Evidence,
		Status:           "open",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, _ = e.store.UpsertIncident(ctx, inc, dedupeWindow)
}

// Submit non-blockingly enqueues a batch of events to the appropriate shard.
func (e *Engine) Submit(batchID int64, events []model.NormalizedEvent) bool {
	if len(events) == 0 {
		return true
	}

	shardIdx := e.shardForAgent(events[0].AgentID)
	target := e.shards[shardIdx]

	select {
	case target.ch <- batchTask{batchID: batchID, events: events}:
		return true
	default:
		return false
	}
}

// ProcessSync synchronously processes an event sequence (useful in unit testing).
func (e *Engine) ProcessSync(events []model.NormalizedEvent) []Finding {
	var allFindings []Finding
	agentStates := make(map[string]*HostState)

	for i := range events {
		ev := &events[i]
		e.metrics.eventsTotal.Add(1)

		st, exists := agentStates[ev.AgentID]
		if !exists {
			st = NewHostState(ev.AgentID)
			agentStates[ev.AgentID] = st
		}

		st.UpdateState(ev)

		for _, r := range e.rules {
			findings := r.Evaluate(ev, st, e.policy)
			for _, f := range findings {
				allFindings = append(allFindings, f)
				e.handleFinding(ev, st, f)
			}
		}
	}

	return allFindings
}

func (e *Engine) shardForAgent(agentID string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentID))
	return int(h.Sum32()) % e.numSh
}

// IngestEventsTotal returns the total count of events processed.
func (e *Engine) IngestEventsTotal() int64 {
	return int64(e.metrics.eventsTotal.Load())
}

// DetectLagMsP95 returns the 95th percentile detection processing lag in milliseconds.
func (e *Engine) DetectLagMsP95() float64 {
	return e.metrics.P95LagMs()
}

// OpenIncidentsCount returns the current count of active open incidents.
func (e *Engine) OpenIncidentsCount(ctx context.Context) int {
	if e.store == nil {
		return 0
	}
	count, err := e.store.CountOpenIncidents(ctx)
	if err != nil {
		return 0
	}
	return count
}

// Stop drains all worker channels and waits for workers to terminate.
func (e *Engine) Stop(ctx context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
