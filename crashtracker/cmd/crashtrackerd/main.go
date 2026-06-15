package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/DataDog/dd-otel-host-profiler/crashtracker/collector"
	"github.com/DataDog/dd-otel-host-profiler/crashtracker/config"
	"github.com/DataDog/dd-otel-host-profiler/crashtracker/correlator"
	"github.com/DataDog/dd-otel-host-profiler/crashtracker/reporter"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := config.DefaultConfig()
	cfg.LoadFromEnv()

	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("received shutdown signal")
		cancel()
	}()

	coll := collector.New(&cfg, logger)
	corr := correlator.New(cfg.DedupWindow)
	rep := reporter.NewErrorsIntake(&cfg)

	if err := coll.Start(ctx); err != nil {
		logger.Error("failed to start collector", "error", err)
		return 1
	}
	defer coll.Stop()

	logger.Info("crashtracker daemon started",
		"signals", cfg.Signals,
		"agent_url", cfg.AgentURL,
		"core_handler", cfg.UseCoreHandler,
	)

	go func() {
		for event := range coll.Events() {
			switch event.EventType {
			case collector.EventTypeSignal, collector.EventTypeOOM:
				corr.HandleSignalEvent(event)
			case collector.EventTypeConfirmed:
				corr.HandleConfirmation(event.PID)
			}
		}
	}()

	go func() {
		for pc := range corr.Complete() {
			if pc.Report != nil {
				if err := rep.Report(pc.Report); err != nil {
					logger.Error("failed to report crash", "pid", pc.Event.PID, "error", err)
				}
			}
		}
	}()

	<-ctx.Done()

	logger.Info("crashtracker daemon shutting down")
	if err := rep.Close(); err != nil {
		logger.Error("reporter close error", "error", err)
	}
	return 0
}
