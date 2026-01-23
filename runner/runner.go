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
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	ddtracer "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/profiler"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/sys/unix"

	"github.com/DataDog/dd-otel-host-profiler/config"
	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
	"github.com/DataDog/dd-otel-host-profiler/reporter"
	"github.com/DataDog/dd-otel-host-profiler/reporter/oom"
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

func startTraceHandling(ctx context.Context, trc *tracer.Tracer) error {
	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %w", err)
	}

	go func() {
		// Poll the output channels
		for {
			select {
			case trace := <-traceCh:
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
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

func kernelSupportsNamedAnonymousMappings() bool {
	// Check for PR_SET_VMA support with PR_SET_VMA_ANON_NAME.
	// Calling with 0 length is a no-op that returns 0 if supported,
	// and EINVAL if the syscall or option is not supported.
	err := unix.Prctl(unix.PR_SET_VMA, unix.PR_SET_VMA_ANON_NAME, 0, 0, 0)
	return err == nil
}

func Run(mainCtx context.Context, c *config.Config) ExitCode {
	versionInfo := version.GetVersionInfo()

	kernVersion, err := getKernelVersion()
	if err != nil {
		return failure("Failed to get kernel version", "error", err)
	}

	if code := sanityCheck(c, kernVersion); code != ExitSuccess {
		return code
	}

	currentScore, err := oom.GetOOMScoreAdj(0)
	if err != nil {
		slog.Warn("Failed to get OOM score adjustment", slog.String("error", err.Error()))
	} else if currentScore > 0 {
		if err = oom.SetOOMScoreAdj(0, 0); err != nil {
			slog.Warn("Could not adjust OOM score", slog.String("error", err.Error()))
		}
	}

	if c.EnableGoRuntimeProfiler {
		addr, _ := strings.CutPrefix(c.AgentURL, "http://")
		opts := []profiler.Option{
			profiler.WithService("dd-otel-host-self-profiler"),
			profiler.WithEnv(c.Environment),
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
		if c.GoRuntimeProfilerPeriod > 0 {
			opts = append(opts, profiler.WithPeriod(c.GoRuntimeProfilerPeriod))
		}
		err = profiler.Start(opts...)
		if err != nil {
			failure("failed to start the runtime profiler", "error", err)
		}
		defer profiler.Stop()
	}

	if c.GoRuntimeMetricsStatsdAddress != "" {
		addr, _ := strings.CutPrefix(c.AgentURL, "http://")
		err = ddtracer.Start(
			ddtracer.WithService("dd-otel-host-self-profiler"),
			ddtracer.WithEnv(c.Environment),
			ddtracer.WithServiceVersion(versionInfo.Version),
			ddtracer.WithAgentAddr(addr),
			ddtracer.WithDogstatsdAddr(c.GoRuntimeMetricsStatsdAddress),
			ddtracer.WithTraceEnabled(false),
		)
		if err != nil {
			failure("failed to start the tracer", "error", err)
		}
		defer ddtracer.Stop()
	}

	slog.Info("Starting Datadog OTEL host profiler",
		slog.String("version", versionInfo.Version),
		slog.String("revision", versionInfo.VcsRevision),
		slog.String("date", versionInfo.VcsTime),
		slog.String("arch", runtime.GOARCH))

	if err = tracer.ProbeBPFSyscall(); err != nil {
		return failure("Failed to probe eBPF syscall", "error", err)
	}

	intervals := times.New(c.ReporterInterval, c.MonitorInterval,
		c.ProbabilisticInterval)

	metrics.Start(noop.Meter{})

	// Start periodic synchronization with the realtime clock
	times.StartRealtimeSync(mainCtx, c.ClockSyncInterval)

	slog.Debug("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(c.Tracers)
	if err != nil {
		return failure("Failed to parse the included tracers", "error", err)
	}

	// Disable Go interpreter because we are doing Go symbolization remotely.
	includeTracers.Disable(tracertypes.GoTracer)
	if c.CollectContext {
		includeTracers.Enable(tracertypes.Labels)
	} else {
		includeTracers.Disable(tracertypes.Labels)
	}
	slog.Info("Enabled tracers", slog.String("tracers", includeTracers.String()))

	validatedTags := config.ValidateTags(c.Tags)
	slog.Debug("Validated tags", slog.String("tags", validatedTags.String()))

	// Add tags from the arguments
	config.AddTagsFromArgs(&validatedTags, c)

	var containerMetadataProvider containermetadata.Provider
	if c.EnableSplitByService {
		// If we're splitting by service, we only need the container ID because Datadog
		// agent will add the rest of the metadata.
		containerMetadataProvider = containermetadata.NewContainerIDProvider()
	} else {
		containerMetadataProvider, err =
			containermetadata.NewContainerMetadataProvider(mainCtx, c.Node)
		if err != nil {
			return failure("Failed to create container metadata provider", "error", err)
		}
	}

	var validSymbolEndpoints []reporter.SymbolEndpoint

	if c.UploadSymbols {
		validSymbolEndpoints = GetValidSymbolEndpoints(c.Site, c.APIKey, c.AppKey, c.AdditionalSymbolEndpoints, func(msg string) {
			slog.Info(msg)
		}, func(msg string) {
			slog.Warn(msg)
		})
	}

	var intakeURL string
	apiKey := ""
	if c.Agentless {
		if c.APIKey == "" {
			return failure("Datadog API key is required when running in agentless mode")
		}
		intakeURL, err = config.IntakeURLForSite(c.Site)
		if err != nil {
			return failure("Failed to get agentless URL from site", "site", c.Site, "error", err)
		}
		apiKey = c.APIKey
	} else {
		intakeURL, err = config.IntakeURLForAgent(c.AgentURL)
		if err != nil {
			return failure("Failed to get intake URL from agent URL", "agent_url", c.AgentURL, "error", err)
		}
	}

	if c.HostServiceName == "" && !c.EnableSplitByService {
		return failure("Service name is required when running in non-split-by-service mode")
	}
	if c.HostServiceName != "" && c.EnableSplitByService {
		slog.Warn("Running in split-by-service mode with a host service name, the values of --host-service flag and DD_HOST_PROFILING_SERVICE environment variable will be discarded")
	}

	useRuntimeIDInServiceEntityKey := c.EnableSplitByService && c.CollectContext
	rep, err := reporter.NewDatadog(mainCtx, &reporter.Config{
		IntakeURL:                            intakeURL,
		Version:                              versionInfo.Version,
		ReportInterval:                       intervals.ReportInterval(),
		ExecutablesCacheElements:             defaultExecutablesCacheSize,
		ProcessesCacheElements:               defaultProcessesCacheSize,
		SamplesPerSecond:                     int(c.SamplesPerSecond),
		PprofPrefix:                          c.PprofPrefix,
		Tags:                                 validatedTags,
		Timeline:                             c.Timeline,
		APIKey:                               apiKey,
		EnableSplitByService:                 c.EnableSplitByService,
		SplitServiceSuffix:                   c.SplitServiceSuffix,
		HostServiceName:                      c.HostServiceName,
		CollectContext:                       c.CollectContext,
		UseRuntimeIDInServiceEntityKey:       useRuntimeIDInServiceEntityKey,
		KernelSupportsNamedAnonymousMappings: kernelSupportsNamedAnonymousMappings(),
		SymbolUploaderConfig: reporter.SymbolUploaderConfig{
			SymbolUploaderOptions: reporter.SymbolUploaderOptions{
				Enabled:              c.UploadSymbols,
				UploadDynamicSymbols: c.UploadDynamicSymbols,
				UploadGoPCLnTab:      c.UploadGoPCLnTab,
				UseHTTP2:             c.UploadSymbolsHTTP2,
				SymbolQueryInterval:  c.UploadSymbolQueryInterval,
				DryRun:               c.UploadSymbolsDryRun,
				SymbolEndpoints:      validSymbolEndpoints,
			},
			Version: versionInfo.Version,
		},
	}, containerMetadataProvider)
	if err != nil {
		return failure("Failed to create Datadog reporter", "error", err)
	}

	err = rep.Start(mainCtx)
	if err != nil {
		return failure("Failed to start reporting", "error", err)
	}

	includeEnvVars := libpf.Set[string]{}
	if c.EnableSplitByService {
		for _, envVar := range reporter.ServiceNameEnvVars {
			includeEnvVars[envVar] = libpf.Void{}
		}
	}

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		ExecutableReporter:     rep,
		TraceReporter:          rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		FilterErrorFrames:      !c.SendErrorFrames,
		FilterIdleFrames:       !c.SendIdleFrames,
		SamplesPerSecond:       int(c.SamplesPerSecond),
		MapScaleFactor:         int(c.MapScaleFactor),
		KernelVersionCheck:     !c.NoKernelVersionCheck,
		VerboseMode:            c.VerboseeBPF,
		BPFVerifierLogLevel:    uint32(c.BPFVerifierLogLevel),
		ProbabilisticInterval:  c.ProbabilisticInterval,
		ProbabilisticThreshold: uint(c.ProbabilisticThreshold),
		IncludeEnvVars:         includeEnvVars,
	})
	if err != nil {
		return failure("Failed to load eBPF tracer", "error", err)
	}
	slog.Info("eBPF tracer loaded")
	defer trc.Close()

	now := time.Now()
	trc.StartPIDEventProcessor(mainCtx)

	metrics.Add(metrics.IDProcPIDStartupMs, metrics.MetricValue(time.Since(now).Milliseconds()))
	slog.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(); err != nil {
		return failure("Failed to attach to perf event", "error", err)
	}
	slog.Info("Attached tracer program")

	if c.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(mainCtx)
		slog.Info("Enabled probabilistic profiling")
	} else {
		if err := trc.EnableProfiling(); err != nil {
			return failure("Failed to enable perf events", "error", err)
		}
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return failure("Failed to attach scheduler monitor", "error", err)
	}
	// This log line is used in our system tests to verify if that the agent has started. So if you
	// change this log line update also the system test.
	slog.Info("Attached sched monitor")

	if err := startTraceHandling(mainCtx, trc); err != nil {
		return failure("Failed to start trace handling", "error", err)
	}

	if c.VerboseeBPF {
		slog.Info("Reading from trace_pipe...")
		go readTracePipe(mainCtx)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	slog.Info("Stop processing ...")
	rep.Stop()

	slog.Info("Exiting ...")
	return ExitSuccess
}

// GetValidSymbolEndpoints returns a list of valid symbol endpoints
// Note: This function is used in datadog-agent repository.
func GetValidSymbolEndpoints(
	site string,
	apiKey string,
	appKey string,
	additionalSymbolEndpoints []reporter.SymbolEndpoint,
	info func(string),
	warn func(string)) []reporter.SymbolEndpoint {
	validSites := make([]string, 0)
	var validSymbolEndpoints []reporter.SymbolEndpoint

	var symbolEndpoints []reporter.SymbolEndpoint
	symbolEndpoints = append(symbolEndpoints, additionalSymbolEndpoints...)
	symbolEndpoints = appendEndpoint(symbolEndpoints, site, apiKey, appKey)

	for _, e := range symbolEndpoints {
		validationErr := validateSymbolEndpoint(e.Site, e.APIKey, e.AppKey)
		if validationErr != nil {
			warn(fmt.Sprintf("Error to validate symbol endpoint: %v", validationErr))
		} else {
			validSymbolEndpoints = append(validSymbolEndpoints, e)
			validSites = append(validSites, e.Site)
		}
	}

	if len(validSymbolEndpoints) == 0 {
		warn("No valid symbol endpoint is configured. Will not upload symbols.")
	} else {
		info("Enabling Datadog local symbol upload to the following sites: " + strings.Join(validSites, ", "))
	}

	return validSymbolEndpoints
}

func sanityCheck(c *config.Config, kernVersion kernelVersion) ExitCode {
	if c.SamplesPerSecond < 1 {
		return ParseError("Invalid sampling frequency", "samples_per_second", c.SamplesPerSecond)
	}

	if c.MapScaleFactor > 8 {
		return ParseError("eBPF map scaling factor exceeds limit",
			"map_scale_factor", c.MapScaleFactor, "max", config.MaxArgMapScaleFactor)
	}

	if c.BPFVerifierLogLevel > 2 {
		return ParseError("Invalid eBPF verifier log level", "level", c.BPFVerifierLogLevel)
	}

	if c.ProbabilisticInterval < 1*time.Minute || c.ProbabilisticInterval > 5*time.Minute {
		return ParseError("Invalid argument for probabilistic-interval: use " +
			"a duration between 1 and 5 minutes")
	}

	if c.ProbabilisticThreshold < 1 ||
		c.ProbabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return ParseError("Invalid argument for probabilistic-threshold",
			"value", c.ProbabilisticThreshold,
			"min", 1,
			"max", tracer.ProbabilisticThresholdMax)
	}

	if !c.NoKernelVersionCheck {
		var minMajor, minMinor uint32
		switch runtime.GOARCH {
		case "amd64":
			minMajor, minMinor = 4, 19
		case "arm64":
			// Older ARM64 kernel versions have broken bpf_probe_read.
			// https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47
			minMajor, minMinor = 5, 5
		default:
			return failure("Unsupported architecture", "arch", runtime.GOARCH)
		}

		if kernVersion.major < minMajor || (kernVersion.major == minMajor && kernVersion.minor < minMinor) {
			return failure("Host Agent requires kernel version or newer",
				"min_major", minMajor,
				"min_minor", minMinor,
				"actual_major", kernVersion.major,
				"actual_minor", kernVersion.minor,
				"actual_patch", kernVersion.patch)
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
		slog.Info("Could not open trace_pipe", slog.String("mount", mnt), slog.String("error", err.Error()))
	}
	return nil, os.ErrNotExist
}

func readTracePipe(ctx context.Context) {
	tp, err := getTracePipe()
	if err != nil {
		slog.Warn("Could not open trace_pipe, check that tracefs is mounted")
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
			slog.Error("error reading trace_pipe", slog.String("error", err.Error()))
			return
		}
		line = strings.TrimSpace(line)
		if line != "" {
			slog.Info("ebpf-profiler output", slog.String("line", line))
		}
	}
}

func ParseError(msg string, args ...any) ExitCode {
	slog.Error(msg, args...)
	return exitParseError
}

func failure(msg string, args ...any) ExitCode {
	slog.Error(msg, args...)
	return exitFailure
}

func validateSymbolEndpoint(site, apiKey, appKey string) error {
	if site == "" || apiKey == "" {
		return fmt.Errorf("site and API key should be set and non-empty strings for site %s", site)
	}
	if !config.IsAPIKeyValid(apiKey) {
		return fmt.Errorf("API key for site %s is not valid", site)
	}
	if appKey != "" && !config.IsAPPKeyValid(appKey) {
		return fmt.Errorf("application key for site %s is not valid", site)
	}
	return nil
}
