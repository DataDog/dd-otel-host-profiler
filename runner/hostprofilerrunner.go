/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

	configpkg "github.com/DataDog/dd-otel-host-profiler/config"
	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
	"github.com/DataDog/dd-otel-host-profiler/reporter"
	"github.com/DataDog/dd-otel-host-profiler/version"
)

type ExitCode int

type kernelVersion struct {
	major uint32
	minor uint32
	patch uint32
}

const (
	ExitSuccess ExitCode = 0
	exitFailure ExitCode = 1

	// Go 'flag' package calls os.Exit(2) on flag parse errors, if ExitOnError is set
	exitParseError ExitCode = 2

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

func getKernelVersion() (kernelVersion, error) {
	major, minor, patch, err := tracer.GetCurrentKernelVersion()
	if err != nil {
		return kernelVersion{}, err
	}
	return kernelVersion{major: major, minor: minor, patch: patch}, nil
}

func kernelSupportsNamedAnonymousMappings(ver kernelVersion) bool {
	return ver.major > 5 || (ver.major == 5 && ver.minor >= 17)
}

func RunHostProfiler(mainCtx context.Context, config *configpkg.Config) ExitCode {
	versionInfo := version.GetVersionInfo()

	kernVersion, err := getKernelVersion()
	if err != nil {
		return failure("Failed to get kernel version: %v", err)
	}

	if code := sanityCheck(config, kernVersion); code != ExitSuccess {
		return code
	}

	if config.EnableGoRuntimeProfiler {
		addr, _ := strings.CutPrefix(config.AgentURL, "http://")
		opts := []profiler.Option{
			profiler.WithService("dd-otel-host-self-profiler"),
			profiler.WithEnv(config.Environment),
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
		if config.GoRuntimeProfilerPeriod > 0 {
			opts = append(opts, profiler.WithPeriod(config.GoRuntimeProfilerPeriod))
		}
		err = profiler.Start(opts...)
		if err != nil {
			failure("failed to start the runtime profiler: %v", err)
		}
		defer profiler.Stop()
	}

	if config.GoRuntimeMetricsStatsdAddress != "" {
		addr, _ := strings.CutPrefix(config.AgentURL, "http://")
		err = ddtracer.Start(
			ddtracer.WithService("dd-otel-host-self-profiler"),
			ddtracer.WithEnv(config.Environment),
			ddtracer.WithServiceVersion(versionInfo.Version),
			ddtracer.WithAgentAddr(addr),
			ddtracer.WithDogstatsdAddr(config.GoRuntimeMetricsStatsdAddress),
			ddtracer.WithTraceEnabled(false),
		)
		if err != nil {
			failure("failed to start the tracer: %v", err)
		}
		defer ddtracer.Stop()
	}

	log.Infof("Starting Datadog OTEL host profiler v%s (revision: %s, date: %s), arch: %v",
		versionInfo.Version, versionInfo.VcsRevision, versionInfo.VcsTime, runtime.GOARCH)

	if err = tracer.ProbeBPFSyscall(); err != nil {
		return failure("Failed to probe eBPF syscall: %v", err)
	}

	// disable trace handler cache because it consumes too much memory for almost no CPU benefit
	traceHandlerCacheSize := uint32(0)

	intervals := times.New(config.ReporterInterval, config.MonitorInterval,
		config.ProbabilisticInterval)

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(mainCtx, config.ClockSyncInterval)

	log.Debugf("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(config.Tracers)
	if err != nil {
		return failure("Failed to parse the included tracers: %v", err)
	}

	// Disable Go interpreter because we are doing Go symbolization remotely.
	includeTracers.Disable(tracertypes.GoTracer)
	if config.CollectContext {
		includeTracers.Enable(tracertypes.Labels)
	} else {
		includeTracers.Disable(tracertypes.Labels)
	}
	log.Infof("Enabled tracers: %s", includeTracers.String())

	validatedTags := configpkg.ValidateTags(config.Tags)
	log.Debugf("Validated tags: %s", validatedTags)

	// Add tags from the arguments
	configpkg.AddTagsFromArgs(&validatedTags, config)

	var containerMetadataProvider containermetadata.Provider
	if config.EnableSplitByService {
		// If we're splitting by service, we only need the container ID because Datadog
		// agent will add the rest of the metadata.
		containerMetadataProvider = containermetadata.NewContainerIDProvider()
	} else {
		containerMetadataProvider, err =
			containermetadata.NewContainerMetadataProvider(mainCtx, config.Node)
		if err != nil {
			return failure("Failed to create container metadata provider: %v", err)
		}
	}

	var symbolEndpoints = config.AdditionalSymbolEndpoints

	if config.Site != "" && config.APIKey != "" && config.AppKey != "" {
		symbolEndpoints = appendEndpoint(symbolEndpoints, config.Site, config.APIKey, config.AppKey)
	}

	var intakeURL string
	apiKey := ""
	if config.Agentless {
		if config.APIKey == "" {
			return failure("Datadog API key is required when running in agentless mode")
		}
		intakeURL, err = configpkg.IntakeURLForSite(config.Site)
		if err != nil {
			return failure("Failed to get agentless URL from site %v: %v", config.Site, err)
		}
		apiKey = config.APIKey
	} else {
		intakeURL, err = configpkg.IntakeURLForAgent(config.AgentURL)
		if err != nil {
			return failure("Failed to get intake URL from agent URL %v: %v", config.AgentURL, err)
		}
	}

	if config.HostServiceName == "" && !config.EnableSplitByService {
		return failure("Service name is required when running in non-split-by-service mode")
	}
	if config.HostServiceName != "" && config.EnableSplitByService {
		log.Warning("Running in split-by-service mode with a host service name, the values of --host-service flag and DD_HOST_PROFILING_SERVICE environment variable will be discarded")
	}

	rep, err := reporter.NewDatadog(&reporter.Config{
		IntakeURL:                            intakeURL,
		Version:                              versionInfo.Version,
		ReportInterval:                       intervals.ReportInterval(),
		ExecutablesCacheElements:             defaultExecutablesCacheSize,
		ProcessesCacheElements:               defaultProcessesCacheSize,
		SamplesPerSecond:                     int(config.SamplesPerSecond),
		PprofPrefix:                          config.PprofPrefix,
		Tags:                                 validatedTags,
		Timeline:                             config.Timeline,
		APIKey:                               apiKey,
		EnableSplitByService:                 config.EnableSplitByService,
		SplitServiceSuffix:                   config.SplitServiceSuffix,
		HostServiceName:                      config.HostServiceName,
		KernelSupportsNamedAnonymousMappings: kernelSupportsNamedAnonymousMappings(kernVersion),
		SymbolUploaderConfig: reporter.SymbolUploaderConfig{
			Enabled:              config.UploadSymbols,
			UploadDynamicSymbols: config.UploadDynamicSymbols,
			UploadGoPCLnTab:      config.UploadGoPCLnTab,
			UseHTTP2:             config.UploadSymbolsHTTP2,
			SymbolQueryInterval:  config.UploadSymbolQueryInterval,
			DryRun:               config.UploadSymbolsDryRun,
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
	if config.EnableSplitByService {
		for _, envVar := range reporter.ServiceNameEnvVars {
			includeEnvVars[envVar] = libpf.Void{}
		}
	}

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		Reporter:               rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !config.SendErrorFrames,
		SamplesPerSecond:       int(config.SamplesPerSecond),
		MapScaleFactor:         int(config.MapScaleFactor),
		KernelVersionCheck:     !config.NoKernelVersionCheck,
		VerboseMode:            config.VerboseeBPF,
		BPFVerifierLogLevel:    uint32(config.BPFVerifierLogLevel),
		ProbabilisticInterval:  config.ProbabilisticInterval,
		ProbabilisticThreshold: uint(config.ProbabilisticThreshold),
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

	if config.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
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

	traceHandlerIntervals := times.New(config.ReporterInterval, 60*time.Second, config.ProbabilisticInterval)
	if err := startTraceHandling(mainCtx, rep, traceHandlerIntervals, trc, traceHandlerCacheSize); err != nil {
		return failure("Failed to start trace handling: %v", err)
	}

	if config.VerboseeBPF {
		log.Info("Reading from trace_pipe...")
		go readTracePipe(mainCtx)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()

	log.Info("Exiting ...")
	return ExitSuccess
}

func sanityCheck(settings *configpkg.Config, kernVersion kernelVersion) ExitCode {
	if settings.SamplesPerSecond < 1 {
		return ParseError("Invalid sampling frequency: %d", settings.SamplesPerSecond)
	}

	if settings.MapScaleFactor > 8 {
		return ParseError("eBPF map scaling factor %d exceeds limit (max: %d)",
			settings.MapScaleFactor, configpkg.MaxArgMapScaleFactor)
	}

	if settings.BPFVerifierLogLevel > 2 {
		return ParseError("Invalid eBPF verifier log level: %d", settings.BPFVerifierLogLevel)
	}

	if settings.ProbabilisticInterval < 1*time.Minute || settings.ProbabilisticInterval > 5*time.Minute {
		return ParseError("Invalid argument for probabilistic-interval: use " +
			"a duration between 1 and 5 minutes")
	}

	if settings.ProbabilisticThreshold < 1 ||
		settings.ProbabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return ParseError("Invalid argument for probabilistic-threshold. Value "+
			"should be between 1 and %d", tracer.ProbabilisticThresholdMax)
	}

	if !settings.NoKernelVersionCheck {
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

		if kernVersion.major < minMajor || (kernVersion.major == minMajor && kernVersion.minor < minMinor) {
			return failure("Host Agent requires kernel version "+
				"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, kernVersion.major, kernVersion.minor, kernVersion.patch)
		}
	}

	return ExitSuccess
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

func ParseError(msg string, args ...interface{}) ExitCode {
	log.Errorf(msg, args...)
	return exitParseError
}

func failure(msg string, args ...interface{}) ExitCode {
	log.Errorf(msg, args...)
	return exitFailure
}
