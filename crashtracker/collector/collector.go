package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/DataDog/dd-otel-host-profiler/crashtracker/config"
)

const (
	EventTypeSignal    = 1
	EventTypeOOM       = 2
	EventTypeConfirmed = 3
)

// CrashEvent is the Go representation of the BPF crash_event struct.
// It mirrors crashtrackerCrashEvent but with exported-friendly field names.
type CrashEvent struct {
	EventType uint8
	Sig       uint32
	SigCode   uint32
	SigAddr   uint64
	PID       uint32
	TID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	KtimeNs   uint64
	BoottimeNs uint64
	IP        uint64
	SP        uint64
	UserStackLen uint32
	KernStackLen uint32
	UserStack    [128]uint64
	KernStack    [128]uint64
	CgroupID  uint64
	PidNsID   uint32
}

// CommString returns the null-terminated comm field as a Go string.
func (e *CrashEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// Collector loads BPF programs, attaches tracepoints, and reads crash events.
type Collector struct {
	cfg     *config.Config
	logger  *slog.Logger
	eventCh chan CrashEvent

	objs   *crashtrackerObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new Collector.
func New(cfg *config.Config, logger *slog.Logger) *Collector {
	return &Collector{
		cfg:     cfg,
		logger:  logger,
		eventCh: make(chan CrashEvent, 64),
	}
}

// Events returns the channel on which crash events are delivered.
func (c *Collector) Events() <-chan CrashEvent {
	return c.eventCh
}

// Start loads BPF programs, attaches tracepoints, and begins reading the ring buffer.
func (c *Collector) Start(ctx context.Context) error {
	c.logger.Info("loading BPF programs")

	objs := crashtrackerObjects{}
	if err := loadCrashtrackerObjects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	c.objs = &objs

	sigLink, err := link.Tracepoint("signal", "signal_deliver", objs.TracepointSignalSignalDeliver, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach signal:signal_deliver: %w", err)
	}
	c.links = append(c.links, sigLink)

	oomLink, err := link.Tracepoint("oom", "mark_victim", objs.TracepointOomMarkVictim, nil)
	if err != nil {
		c.logger.Warn("failed to attach oom:mark_victim (tracepoint may not exist on this kernel)", "error", err)
	} else {
		c.links = append(c.links, oomLink)
	}

	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.TracepointSchedSchedProcessExit, nil)
	if err != nil {
		c.closeLinks()
		objs.Close()
		return fmt.Errorf("attach sched:sched_process_exit: %w", err)
	}
	c.links = append(c.links, exitLink)

	reader, err := ringbuf.NewReader(objs.CrashEvents)
	if err != nil {
		c.closeLinks()
		objs.Close()
		return fmt.Errorf("create ring buffer reader: %w", err)
	}
	c.reader = reader

	c.logger.Info("BPF programs loaded and attached",
		"tracepoints", len(c.links),
	)

	go c.readLoop(ctx)

	return nil
}

func (c *Collector) readLoop(ctx context.Context) {
	defer close(c.eventCh)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.logger.Error("ring buffer read error", "error", err)
			continue
		}

		event, err := parseCrashEvent(record.RawSample)
		if err != nil {
			c.logger.Error("failed to parse crash event", "error", err)
			continue
		}

		select {
		case c.eventCh <- event:
		case <-ctx.Done():
			return
		}
	}
}

func parseCrashEvent(data []byte) (CrashEvent, error) {
	var raw crashtrackerCrashEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return CrashEvent{}, fmt.Errorf("decode crash event: %w", err)
	}

	var comm [16]byte
	for i, v := range raw.Comm {
		comm[i] = byte(v)
	}

	return CrashEvent{
		EventType:    raw.EventType,
		Sig:          raw.Sig,
		SigCode:      raw.SigCode,
		SigAddr:      raw.SigAddr,
		PID:          raw.Pid,
		TID:          raw.Tid,
		UID:          raw.Uid,
		GID:          raw.Gid,
		Comm:         comm,
		KtimeNs:      raw.KtimeNs,
		BoottimeNs:   raw.BoottimeNs,
		IP:           raw.Ip,
		SP:           raw.Sp,
		UserStackLen: raw.UserStackLen,
		KernStackLen: raw.KernStackLen,
		UserStack:    raw.UserStack,
		KernStack:    raw.KernStack,
		CgroupID:     raw.CgroupId,
		PidNsID:      raw.PidNsId,
	}, nil
}

// Stop gracefully shuts down the collector.
func (c *Collector) Stop() {
	if c.reader != nil {
		c.reader.Close()
	}
	c.closeLinks()
	if c.objs != nil {
		c.objs.Close()
	}
}

func (c *Collector) closeLinks() {
	for _, l := range c.links {
		l.Close()
	}
	c.links = nil
}
