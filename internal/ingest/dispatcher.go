package ingest

import (
	"context"
	"hash/fnv"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

// DispatchItem represents a batch and its events sent to a shard.
type DispatchItem struct {
	BatchID int64
	Events  []model.NormalizedEvent
}

type shard struct {
	ch chan DispatchItem
}

// Dispatcher distributes normalized events across N worker shards with a periodic sweeper for backlogged batches.
type Dispatcher struct {
	shards    []*shard
	numShards int
	store     *storage.Storage
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewDispatcher initializes a new Dispatcher with numShards worker channels.
func NewDispatcher(store *storage.Storage, numShards int) *Dispatcher {
	if numShards <= 0 {
		numShards = runtime.GOMAXPROCS(0)
	}
	shards := make([]*shard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &shard{
			ch: make(chan DispatchItem, 64),
		}
	}

	return &Dispatcher{
		shards:    shards,
		numShards: numShards,
		store:     store,
	}
}

// Start launches the shard worker goroutines and the 5-second pending batch sweeper.
func (d *Dispatcher) Start(ctx context.Context) {
	d.ctx, d.cancel = context.WithCancel(ctx)

	// Start shard workers
	for i := 0; i < d.numShards; i++ {
		d.wg.Add(1)
		go d.runShardWorker(i, d.shards[i])
	}

	// Start 5-second sweeper
	d.wg.Add(1)
	go d.runSweeper()
}

func (d *Dispatcher) runShardWorker(idx int, s *shard) {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			// Drain remaining in channel
			for {
				select {
				case item := <-s.ch:
					d.processItem(item)
				default:
					return
				}
			}
		case item := <-s.ch:
			d.processItem(item)
		}
	}
}

func (d *Dispatcher) processItem(item DispatchItem) {
	// Mark batch as processed
	if d.store != nil && item.BatchID > 0 {
		_ = d.store.MarkBatchProcessed(context.Background(), item.BatchID)
	}
}

func (d *Dispatcher) runSweeper() {
	defer d.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.sweepPendingBatches()
		}
	}
}

func (d *Dispatcher) sweepPendingBatches() {
	if d.store == nil {
		return
	}
	pendingIDs, err := d.store.GetPendingBatches(d.ctx, 64)
	if err != nil || len(pendingIDs) == 0 {
		return
	}

	for _, batchID := range pendingIDs {
		events, err := d.store.GetBatchEvents(d.ctx, batchID)
		if err != nil || len(events) == 0 {
			// Mark empty batch as processed
			_ = d.store.MarkBatchProcessed(d.ctx, batchID)
			continue
		}
		if !d.Submit(batchID, events) {
			// Shards full; leave remaining for next sweep
			break
		}
	}
}

// Submit non-blockingly assigns a batch to a shard based on the agent ID hash.
// If the target shard channel is full, false is returned and the batch remains detect_pending=1 in storage.
func (d *Dispatcher) Submit(batchID int64, events []model.NormalizedEvent) bool {
	if len(events) == 0 {
		if d.store != nil && batchID > 0 {
			_ = d.store.MarkBatchProcessed(context.Background(), batchID)
		}
		return true
	}

	agentID := events[0].AgentID
	shardIdx := d.shardForAgent(agentID)
	target := d.shards[shardIdx]

	select {
	case target.ch <- DispatchItem{BatchID: batchID, Events: events}:
		return true
	default:
		// Shard is full; detect_pending stays 1
		return false
	}
}

func (d *Dispatcher) shardForAgent(agentID string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentID))
	return int(h.Sum32()) % d.numShards
}

// IsBacklogged checks if the count of detect_pending batches exceeds 10,000.
func (d *Dispatcher) IsBacklogged(ctx context.Context) bool {
	if d.store == nil {
		return false
	}
	count, err := d.store.CountPendingBatches(ctx)
	if err != nil {
		return false
	}
	return count > 10000
}

// Stop signals all workers and drains tasks before the shutdown deadline expires.
func (d *Dispatcher) Stop(ctx context.Context) error {
	if d.cancel != nil {
		d.cancel()
	}

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[Dispatcher] All shards drained successfully.")
		return nil
	case <-ctx.Done():
		log.Println("[Dispatcher] Shutdown deadline reached before drain completed.")
		return ctx.Err()
	}
}
