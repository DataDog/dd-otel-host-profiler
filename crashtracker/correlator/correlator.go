package correlator

import (
	"sync"
	"time"

	"github.com/DataDog/dd-otel-host-profiler/crashtracker/collector"
	"github.com/DataDog/dd-otel-host-profiler/crashtracker/model"
)

// State represents the lifecycle of a crash event.
type State int

const (
	StatePending   State = iota // Signal received, awaiting confirmation
	StateConfirmed              // Process exit confirmed the crash
	StateEnriched               // Core handler data received
	StateComplete               // Ready to report
	StateDiscarded              // Handled signal, not a real crash
)

// PendingCrash tracks a crash through its lifecycle.
type PendingCrash struct {
	Event      collector.CrashEvent
	State      State
	ReceivedAt time.Time
	Confirmed  bool
	Enrichment *Enrichment
	Report     *model.CrashInfo
}

// Enrichment holds data collected by the core pattern handler.
type Enrichment struct {
	Maps      string
	Status    string
	Cgroup    string
	Environ   map[string]string
	Registers map[string]string
	Threads   []model.ThreadData
}

// Correlator matches BPF events with exit confirmations and core handler data.
// It is safe for concurrent use from multiple goroutines.
//
// Concurrency model:
//   - Ring buffer reader goroutine calls HandleSignalEvent/HandleConfirmation
//   - Core handler socket goroutine calls HandleEnrichment
//   - Timer goroutine calls PurgeExpired
//   - Reporter goroutine reads from Complete()
type Correlator struct {
	mu             sync.Mutex
	pending        map[uint32]*PendingCrash // PID -> pending crash
	confirmTimeout time.Duration

	// earlyConfirms holds PIDs where confirmation arrived before the signal event.
	// This handles the (rare) case where sched_process_exit is processed
	// before signal_deliver due to goroutine scheduling.
	earlyConfirms map[uint32]time.Time

	// completeCh is unbuffered — completed crashes are dispatched without
	// holding the mutex to prevent deadlocks.
	completeCh chan *PendingCrash
}

// New creates a new Correlator.
func New(confirmTimeout time.Duration) *Correlator {
	return &Correlator{
		pending:        make(map[uint32]*PendingCrash),
		earlyConfirms:  make(map[uint32]time.Time),
		confirmTimeout: confirmTimeout,
		completeCh:     make(chan *PendingCrash, 128),
	}
}

// Complete returns the channel on which fully-assembled crashes are delivered.
func (c *Correlator) Complete() <-chan *PendingCrash {
	return c.completeCh
}

// HandleSignalEvent processes a new crash signal or OOM event from BPF.
func (c *Correlator) HandleSignalEvent(event collector.CrashEvent) {
	c.mu.Lock()

	pid := event.PID

	// If there's already a pending crash for this PID (multi-thread crash),
	// keep the first one — it has the original crashing thread's stack.
	if _, exists := c.pending[pid]; exists {
		c.mu.Unlock()
		return
	}

	pc := &PendingCrash{
		Event:      event,
		State:      StatePending,
		ReceivedAt: time.Now(),
	}

	// OOM events are always fatal — no confirmation needed
	if event.EventType == collector.EventTypeOOM {
		pc.Confirmed = true
		pc.State = StateConfirmed
	}

	// Check if confirmation arrived early (before this signal event)
	if _, early := c.earlyConfirms[pid]; early {
		pc.Confirmed = true
		pc.State = StateConfirmed
		delete(c.earlyConfirms, pid)
	}

	c.pending[pid] = pc
	completed := c.tryComplete(pid)
	c.mu.Unlock()

	// Send outside the lock to prevent deadlock if channel is full
	if completed != nil {
		c.completeCh <- completed
	}
}

// HandleConfirmation processes a crash confirmation (process exited due to signal).
func (c *Correlator) HandleConfirmation(pid uint32) {
	c.mu.Lock()

	pc, ok := c.pending[pid]
	if !ok {
		// Confirmation arrived before the signal event — remember it
		c.earlyConfirms[pid] = time.Now()
		c.mu.Unlock()
		return
	}

	pc.Confirmed = true
	if pc.State == StatePending {
		pc.State = StateConfirmed
	}
	completed := c.tryComplete(pid)
	c.mu.Unlock()

	if completed != nil {
		c.completeCh <- completed
	}
}

// HandleEnrichment processes data from the core pattern handler.
func (c *Correlator) HandleEnrichment(pid uint32, enrichment *Enrichment) {
	c.mu.Lock()

	pc, ok := c.pending[pid]
	if !ok {
		c.mu.Unlock()
		return
	}

	pc.Enrichment = enrichment
	if pc.State == StatePending || pc.State == StateConfirmed {
		pc.State = StateEnriched
	}
	completed := c.tryComplete(pid)
	c.mu.Unlock()

	if completed != nil {
		c.completeCh <- completed
	}
}

// tryComplete checks if a crash is ready to report. Returns the PendingCrash
// if complete, nil otherwise. Must be called with mu held.
func (c *Correlator) tryComplete(pid uint32) *PendingCrash {
	pc := c.pending[pid]
	if pc == nil {
		return nil
	}

	if pc.Confirmed {
		pc.State = StateComplete
		delete(c.pending, pid)
		return pc
	}
	return nil
}

// PurgeExpired removes pending crashes that were never confirmed (handled signals)
// and stale early confirmations.
func (c *Correlator) PurgeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for pid, pc := range c.pending {
		if now.Sub(pc.ReceivedAt) > c.confirmTimeout {
			pc.State = StateDiscarded
			delete(c.pending, pid)
		}
	}

	// Also purge stale early confirmations (shouldn't accumulate, but defensive)
	for pid, ts := range c.earlyConfirms {
		if now.Sub(ts) > c.confirmTimeout {
			delete(c.earlyConfirms, pid)
		}
	}
}

// Len returns the number of pending (unresolved) crashes. Useful for metrics.
func (c *Correlator) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}
