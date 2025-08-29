/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	ddtracer "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/profiler"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	otelreporter "go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"golang.org/x/sys/unix"

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

	defaultExecutablesCacheSize = 65536
	defaultProcessesCacheSize   = 16384
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

func appendEndpoint(symbolEndpoints []reporter.SymbolEndpoint, site, apiKey, appKey string) []reporter.SymbolEndpoint {
	// Ensure this exact endpoint has not already been added.
	for _, endpoint := range symbolEndpoints {
		if site == endpoint.Site && apiKey == endpoint.APIKey && appKey == endpoint.AppKey {
			return symbolEndpoints
		}
	}
	return append(symbolEndpoints, reporter.SymbolEndpoint{Site: site, APIKey: apiKey, AppKey: appKey})
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

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if args.verboseMode {
		log.SetLevel(log.DebugLevel)
		// Dump the arguments in debug mode.
		args.dump()
	}

	return runHostProfiler(&args.FullHostProfilerSettings, mainCtx)
}

func runHostProfiler(settings *FullHostProfilerSettings, mainCtx context.Context) exitCode {
	versionInfo := version.GetVersionInfo()

	if code := sanityCheck(settings); code != exitSuccess {
		return code
	}

	if settings.enableGoRuntimeProfiler {
		addr, _ := strings.CutPrefix(settings.agentURL, "http://")
		opts := []profiler.Option{
			profiler.WithService("dd-otel-host-self-profiler"),
			profiler.WithEnv(settings.environment),
			profiler.WithVersion(versionInfo.Version),
			profiler.WithAgentAddr(addr),
			profiler.MutexProfileFraction(100),
			profiler.WithProfileTypes(
				profiler.CPUProfile,
				profiler.HeapProfile,
				profiler.GoroutineProfile,
				profiler.MutexProfile,
			),
		}
		if settings.goRuntimeProfilerPeriod > 0 {
			opts = append(opts, profiler.WithPeriod(settings.goRuntimeProfilerPeriod))
		}
		err := profiler.Start(opts...)
		if err != nil {
			failure("failed to start the runtime profiler: %v", err)
		}
		defer profiler.Stop()
	}

	if settings.goRuntimeMetricsStatsdAddress != "" {
		addr, _ := strings.CutPrefix(settings.agentURL, "http://")
		err := ddtracer.Start(
			ddtracer.WithService("dd-otel-host-self-profiler"),
			ddtracer.WithEnv(settings.environment),
			ddtracer.WithServiceVersion(versionInfo.Version),
			ddtracer.WithAgentAddr(addr),
			ddtracer.WithDogstatsdAddr(settings.goRuntimeMetricsStatsdAddress),
			ddtracer.WithTraceEnabled(false),
		)
		if err != nil {
			failure("failed to start the tracer: %v", err)
		}
		defer ddtracer.Stop()
	}

	log.Infof("Starting Datadog OTEL host profiler v%s (revision: %s, date: %s), arch: %v",
		versionInfo.Version, versionInfo.VcsRevision, versionInfo.VcsTime, runtime.GOARCH)

	if err := tracer.ProbeBPFSyscall(); err != nil {
		return failure("Failed to probe eBPF syscall: %v", err)
	}

	// disable trace handler cache because it consumes too much memory for almost no CPU benefit
	traceHandlerCacheSize := uint32(0)

	intervals := times.New(settings.reporterInterval, settings.monitorInterval,
		settings.probabilisticInterval)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(mainCtx, settings.clockSyncInterval)

	log.Debugf("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(settings.tracers)
	if err != nil {
		return failure("Failed to parse the included tracers: %v", err)
	}

	// Disable Go interpreter because we are doing Go symbolization remotely.
	includeTracers.Disable(tracertypes.GoTracer)
	if settings.collectContext {
		includeTracers.Enable(tracertypes.Labels)
	} else {
		includeTracers.Disable(tracertypes.Labels)
	}
	log.Infof("Enabled tracers: %s", includeTracers.String())

	validatedTags := ValidateTags(settings.tags)
	log.Debugf("Validated tags: %s", validatedTags)

	// Add tags from the arguments
	addTagsFromArgs(&validatedTags, settings)

	var containerMetadataProvider containermetadata.Provider
	if settings.enableSplitByService {
		// If we're splitting by service, we only need the container ID because Datadog
		// agent will add the rest of the metadata.
		containerMetadataProvider = containermetadata.NewContainerIDProvider()
	} else {
		containerMetadataProvider, err =
			containermetadata.NewContainerMetadataProvider(mainCtx, settings.node)
		if err != nil {
			return failure("Failed to create container metadata provider: %v", err)
		}
	}

	var symbolEndpoints = settings.additionalSymbolEndpoints

	if settings.site != "" && settings.apiKey != "" && settings.appKey != "" {
		symbolEndpoints = appendEndpoint(symbolEndpoints, settings.site, settings.apiKey, settings.appKey)
	}

	var intakeURL string
	apiKey := ""
	if settings.agentless {
		if settings.apiKey == "" {
			return failure("Datadog API key is required when running in agentless mode")
		}
		intakeURL, err = intakeURLForSite(settings.site)
		if err != nil {
			return failure("Failed to get agentless URL from site %v: %v", settings.site, err)
		}
		apiKey = settings.apiKey
	} else {
		intakeURL, err = intakeURLForAgent(settings.agentURL)
		if err != nil {
			return failure("Failed to get intake URL from agent URL %v: %v", settings.agentURL, err)
		}
	}

	if settings.hostServiceName == "" && !settings.enableSplitByService {
		return failure("Service name is required when running in non-split-by-service mode")
	}
	if settings.hostServiceName != "" && settings.enableSplitByService {
		log.Warning("Running in split-by-service mode with a host service name, the values of --host-service flag and DD_HOST_PROFILING_SERVICE environment variable will be discarded")
	}

	rep, err := reporter.NewDatadog(&reporter.Config{
		IntakeURL:                intakeURL,
		Version:                  versionInfo.Version,
		ReportInterval:           intervals.ReportInterval(),
		ExecutablesCacheElements: defaultExecutablesCacheSize,
		ProcessesCacheElements:   defaultProcessesCacheSize,
		SamplesPerSecond:         int(settings.samplesPerSecond),
		PprofPrefix:              settings.pprofPrefix,
		Tags:                     validatedTags,
		Timeline:                 settings.timeline,
		APIKey:                   apiKey,
		EnableSplitByService:     settings.enableSplitByService,
		SplitServiceSuffix:       settings.splitServiceSuffix,
		HostServiceName:          settings.hostServiceName,
		SymbolUploaderConfig: reporter.SymbolUploaderConfig{
			Enabled:              settings.uploadSymbols,
			UploadDynamicSymbols: settings.uploadDynamicSymbols,
			UploadGoPCLnTab:      settings.uploadGoPCLnTab,
			UseHTTP2:             settings.uploadSymbolsHTTP2,
			SymbolQueryInterval:  settings.uploadSymbolQueryInterval,
			DryRun:               settings.uploadSymbolsDryRun,
			SymbolEndpoints:      symbolEndpoints,
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

	includeEnvVars := libpf.Set[string]{}
	if settings.enableSplitByService {
		for _, envVar := range reporter.ServiceNameEnvVars {
			includeEnvVars[envVar] = libpf.Void{}
		}
	}

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		Reporter:               rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !settings.sendErrorFrames,
		SamplesPerSecond:       int(settings.samplesPerSecond),
		MapScaleFactor:         int(settings.mapScaleFactor),
		KernelVersionCheck:     !settings.noKernelVersionCheck,
		VerboseMode:            settings.verboseeBPF,
		BPFVerifierLogLevel:    uint32(settings.bpfVerifierLogLevel),
		ProbabilisticInterval:  settings.probabilisticInterval,
		ProbabilisticThreshold: uint(settings.probabilisticThreshold),
		IncludeEnvVars:         includeEnvVars,
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

	if settings.probabilisticThreshold < tracer.ProbabilisticThresholdMax {
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

	traceHandlerIntervals := times.New(settings.reporterInterval, 60*time.Second, settings.probabilisticInterval)
	if err := startTraceHandling(mainCtx, rep, traceHandlerIntervals, trc, traceHandlerCacheSize); err != nil {
		return failure("Failed to start trace handling: %v", err)
	}

	if settings.verboseeBPF {
		log.Info("Reading from trace_pipe...")
		go readTracePipe(mainCtx)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()

	log.Info("Exiting ...")
	return exitSuccess
}

func sanityCheck(settings *FullHostProfilerSettings) exitCode {
	if settings.samplesPerSecond < 1 {
		return parseError("Invalid sampling frequency: %d", settings.samplesPerSecond)
	}

	if settings.mapScaleFactor > 8 {
		return parseError("eBPF map scaling factor %d exceeds limit (max: %d)",
			settings.mapScaleFactor, maxArgMapScaleFactor)
	}

	if settings.bpfVerifierLogLevel > 2 {
		return parseError("Invalid eBPF verifier log level: %d", settings.bpfVerifierLogLevel)
	}

	if settings.probabilisticInterval < 1*time.Minute || settings.probabilisticInterval > 5*time.Minute {
		return parseError("Invalid argument for probabilistic-interval: use " +
			"a duration between 1 and 5 minutes")
	}

	if settings.probabilisticThreshold < 1 ||
		settings.probabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return parseError("Invalid argument for probabilistic-threshold. Value "+
			"should be between 1 and %d", tracer.ProbabilisticThresholdMax)
	}

	if !settings.noKernelVersionCheck {
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

func getTracePipe() (*os.File, error) {
	for _, mnt := range []string{
		"/sys/kernel/debug/tracing",
		"/sys/kernel/tracing"} {
		t, err := os.Open(mnt + "/trace_pipe")
		if err == nil {
			return t, nil
		}
		log.Infof("Could not open trace_pipe at %s: %s", mnt, err)
	}
	return nil, os.ErrNotExist
}

func readTracePipe(ctx context.Context) {
	tp, err := getTracePipe()
	if err != nil {
		log.Warning("Could not open trace_pipe, check that debugfs is mounted")
		return
	}

	// When we're done kick ReadString out of blocked I/O.
	go func() {
		<-ctx.Done()
		tp.Close()
	}()

	r := bufio.NewReader(tp)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			log.Error(err)
			return
		}
		line = strings.TrimSpace(line)
		if line != "" {
			log.Infof("ebpf-profiler: %s", line)
		}
	}
}

func parseError(msg string, args ...interface{}) exitCode {
	log.Errorf(msg, args...)
	return exitParseError
}

func failure(msg string, args ...interface{}) exitCode {
	log.Errorf(msg, args...)
	return exitFailure
}
