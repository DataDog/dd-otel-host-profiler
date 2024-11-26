/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tklauser/numcpus"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	otelreporter "go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
	"golang.org/x/sys/unix"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"

	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
	"github.com/DataDog/dd-otel-host-profiler/reporter"
	"github.com/DataDog/dd-otel-host-profiler/version"
)

// Short copyright / license text for eBPF code
const copyright = `Copyright 2024 Datadog, Inc.

For the eBPF code loaded by Universal Profiling Agent into the kernel,
the following license applies (GPLv2 only). You can obtain a copy of the GPLv2 code at:
https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/support/ebpf

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 only,
as published by the Free Software Foundation;

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details:

https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
`

type exitCode int

const (
	exitSuccess exitCode = 0
	exitFailure exitCode = 1

	// Go 'flag' package calls os.Exit(2) on flag parse errors, if ExitOnError is set
	exitParseError exitCode = 2
)

func startTraceHandling(ctx context.Context, rep otelreporter.TraceReporter,
	intervals *times.Times, trc *tracer.Tracer, cacheSize uint32) error {
	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %w", err)
	}

	_, err := tracehandler.Start(ctx, rep, trc.TraceProcessor(),
		traceCh, intervals, cacheSize)

	return err
}

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() exitCode {
	args, err := parseArgs()
	if err != nil {
		return parseError("Failure to parse arguments: %v", err)
	}

	if args == nil {
		return exitSuccess
	}

	if args.copyright {
		fmt.Print(copyright)
		return exitSuccess
	}

	versionInfo := version.GetVersionInfo()

	if args.verboseMode {
		log.SetLevel(log.DebugLevel)
		// Dump the arguments in debug mode.
		args.dump()
	}

	if code := sanityCheck(args); code != exitSuccess {
		return code
	}

	if args.enableGoRuntimeProfiler {
		addr, _ := strings.CutPrefix(args.agentURL, "http://")
		err = profiler.Start(
			profiler.WithService("dd-otel-host-self-profiler"),
			profiler.WithEnv(args.environment),
			profiler.WithVersion(versionInfo.Version),
			profiler.WithAgentAddr(addr),
			profiler.MutexProfileFraction(100),
			profiler.WithProfileTypes(
				profiler.CPUProfile,
				profiler.HeapProfile,
				profiler.GoroutineProfile,
				profiler.MutexProfile,
			),
		)
		if err != nil {
			log.Fatal(err)
		}
		defer profiler.Stop()
	}

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	log.Infof("Starting Datadog OTEL host profiler v%s (revision: %s, date: %s), arch: %v",
		versionInfo.Version, versionInfo.VcsRevision, versionInfo.VcsTime, runtime.GOARCH)

	if err = tracer.ProbeBPFSyscall(); err != nil {
		return failure("Failed to probe eBPF syscall: %v", err)
	}

	presentCores, err := numcpus.GetPresent()
	if err != nil {
		return failure("Failed to read CPU file: %v", err)
	}

	traceHandlerCacheSize :=
		traceCacheSize(args.monitorInterval, int(args.samplesPerSecond), uint16(presentCores))

	intervals := times.New(args.reporterInterval, args.monitorInterval,
		args.probabilisticInterval)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(mainCtx, args.clockSyncInterval)

	log.Debugf("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(args.tracers)
	if err != nil {
		return failure("Failed to parse the included tracers: %v", err)
	}

	validatedTags := ValidateTags(args.tags)
	log.Debugf("Validated tags: %s", validatedTags)

	// Add tags from the arguments
	addTagsFromArgs(&validatedTags, args)

	containerMetadataProvider, err :=
		containermetadata.NewContainerMetadataProvider(mainCtx, args.node, intervals.MonitorInterval())
	if err != nil {
		return failure("Failed to create container metadata provider: %v", err)
	}

	var intakeURL string
	apiKey := ""
	if args.agentless {
		if args.apiKey == "" {
			return failure("Datadog API key is required when running in agentless mode")
		}
		intakeURL, err = intakeURLForSite(args.site)
		if err != nil {
			return failure("Failed to get agentless URL from site %v: %v", args.site, err)
		}
		apiKey = args.apiKey
	} else {
		intakeURL, err = intakeURLForAgent(args.agentURL)
		if err != nil {
			return failure("Failed to get intake URL from agent URL %v: %v", args.agentURL, err)
		}
	}

	rep, err := reporter.NewDatadog(&reporter.Config{
		IntakeURL:                intakeURL,
		Version:                  versionInfo.Version,
		ReportInterval:           intervals.ReportInterval(),
		ExecutablesCacheElements: traceHandlerCacheSize,
		// Next step: Calculate FramesCacheElements from numCores and samplingRate.
		FramesCacheElements:    traceHandlerCacheSize,
		ProcessesCacheElements: traceHandlerCacheSize,
		SamplesPerSecond:       int(args.samplesPerSecond),
		PprofPrefix:            args.pprofPrefix,
		Tags:                   validatedTags,
		Timeline:               args.timeline,
		APIKey:                 apiKey,
		SymbolUploaderConfig: reporter.SymbolUploaderConfig{
			Enabled:              args.uploadSymbols,
			UploadDynamicSymbols: args.uploadDynamicSymbols,
			UploadGoPCLnTab:      args.uploadGoPCLnTab,
			DryRun:               args.uploadSymbolsDryRun,
			APIKey:               args.apiKey,
			APPKey:               args.appKey,
			Site:                 args.site,
			Version:              versionInfo.Version,
		},
	}, containerMetadataProvider)
	if err != nil {
		return failure("Failed to create Datadog reporter: %v", err)
	}

	err = rep.Start(mainCtx)
	if err != nil {
		return failure("Failed to start reporting: %v", err)
	}

	metrics.SetReporter(rep)

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		Reporter:               rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !args.sendErrorFrames,
		SamplesPerSecond:       int(args.samplesPerSecond),
		MapScaleFactor:         int(args.mapScaleFactor),
		KernelVersionCheck:     !args.noKernelVersionCheck,
		BPFVerifierLogLevel:    uint32(args.bpfVerifierLogLevel),
		ProbabilisticInterval:  args.probabilisticInterval,
		ProbabilisticThreshold: uint(args.probabilisticThreshold),
	})
	if err != nil {
		return failure("Failed to load eBPF tracer: %v", err)
	}
	log.Printf("eBPF tracer loaded")
	defer trc.Close()

	now := time.Now()
	trc.StartPIDEventProcessor(mainCtx)

	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(); err != nil {
		return failure("Failed to attach to perf event: %v", err)
	}
	log.Info("Attached tracer program")

	if args.probabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(mainCtx)
		log.Printf("Enabled probabilistic profiling")
	} else {
		if err := trc.EnableProfiling(); err != nil {
			return failure("Failed to enable perf events: %v", err)
		}
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return failure("Failed to attach scheduler monitor: %v", err)
	}
	// This log line is used in our system tests to verify if that the agent has started. So if you
	// change this log line update also the system test.
	log.Printf("Attached sched monitor")

	if err := startTraceHandling(mainCtx, rep, intervals, trc, traceHandlerCacheSize); err != nil {
		return failure("Failed to start trace handling: %v", err)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()

	log.Info("Exiting ...")
	return exitSuccess
}

// traceCacheSize defines the maximum number of elements for the caches in tracehandler.
//
// The caches in tracehandler have a size-"processing overhead" trade-off: Every cache miss will
// trigger additional processing for that trace in userspace (Go). For most maps, we use
// maxElementsPerInterval as a base sizing factor. For the tracehandler caches, we also multiply
// with traceCacheIntervals. For typical/small values of maxElementsPerInterval, this can lead to
// non-optimal map sizing (reduced cache_hit:cache_miss ratio and increased processing overhead).
// Simply increasing traceCacheIntervals is problematic when maxElementsPerInterval is large
// (e.g. too many CPU cores present) as we end up using too much memory. A minimum size is
// therefore used here.
func traceCacheSize(monitorInterval time.Duration, samplesPerSecond int,
	presentCPUCores uint16) uint32 {
	const (
		traceCacheIntervals = 6
		traceCacheMinSize   = 65536
	)

	maxElements := maxElementsPerInterval(monitorInterval, samplesPerSecond, presentCPUCores)

	size := maxElements * uint32(traceCacheIntervals)
	if size < traceCacheMinSize {
		size = traceCacheMinSize
	}
	return util.NextPowerOfTwo(size)
}

func maxElementsPerInterval(monitorInterval time.Duration, samplesPerSecond int,
	presentCPUCores uint16) uint32 {
	return uint32(uint16(samplesPerSecond) * uint16(monitorInterval.Seconds()) * presentCPUCores)
}

func sanityCheck(args *arguments) exitCode {
	if args.samplesPerSecond < 1 {
		return parseError("Invalid sampling frequency: %d", args.samplesPerSecond)
	}

	if args.mapScaleFactor > 8 {
		return parseError("eBPF map scaling factor %d exceeds limit (max: %d)",
			args.mapScaleFactor, maxArgMapScaleFactor)
	}

	if args.bpfVerifierLogLevel > 2 {
		return parseError("Invalid eBPF verifier log level: %d", args.bpfVerifierLogLevel)
	}

	if args.probabilisticInterval < 1*time.Minute || args.probabilisticInterval > 5*time.Minute {
		return parseError("Invalid argument for probabilistic-interval: use " +
			"a duration between 1 and 5 minutes")
	}

	if args.probabilisticThreshold < 1 ||
		args.probabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return parseError("Invalid argument for probabilistic-threshold. Value "+
			"should be between 1 and %d", tracer.ProbabilisticThresholdMax)
	}

	if !args.noKernelVersionCheck {
		major, minor, patch, err := tracer.GetCurrentKernelVersion()
		if err != nil {
			return failure("Failed to get kernel version: %v", err)
		}

		var minMajor, minMinor uint32
		switch runtime.GOARCH {
		case "amd64":
			minMajor, minMinor = 4, 19
		case "arm64":
			// Older ARM64 kernel versions have broken bpf_probe_read.
			// https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47
			minMajor, minMinor = 5, 5
		default:
			return failure("Unsupported architecture: %s", runtime.GOARCH)
		}

		if major < minMajor || (major == minMajor && minor < minMinor) {
			return failure("Host Agent requires kernel version "+
				"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, major, minor, patch)
		}
	}

	return exitSuccess
}

func parseError(msg string, args ...interface{}) exitCode {
	log.Errorf(msg, args...)
	return exitParseError
}

func failure(msg string, args ...interface{}) exitCode {
	log.Errorf(msg, args...)
	return exitFailure
}
