// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"go.opentelemetry.io/ebpf-profiler/tracer"

	"github.com/DataDog/dd-otel-host-profiler/reporter"
	"github.com/DataDog/dd-otel-host-profiler/version"
)

const (
	// Default values for CLI flags
	defaultArgSamplesPerSecond    = 20
	defaultArgReporterInterval    = 60 * time.Second
	defaultArgMonitorInterval     = 5.0 * time.Second
	defaultClockSyncInterval      = 3 * time.Minute
	defaultProbabilisticThreshold = tracer.ProbabilisticThresholdMax
	defaultProbabilisticInterval  = 1 * time.Minute
	defaultSymbolQueryInterval    = 5 * time.Second
	defaultArgSendErrorFrames     = false
	defaultArgAgentURL            = "http://localhost:8126"

	// This is the X in 2^(n + x) where n is the default hardcoded map size value
	defaultArgMapScaleFactor = 0
	// 1TB of executable address space
	maxArgMapScaleFactor = 8
)

type arguments struct {
	bpfVerifierLogLevel       uint64
	agentURL                  string
	copyright                 bool
	mapScaleFactor            uint64
	monitorInterval           time.Duration
	clockSyncInterval         time.Duration
	noKernelVersionCheck      bool
	node                      string
	probabilisticInterval     time.Duration
	probabilisticThreshold    uint64
	reporterInterval          time.Duration
	samplesPerSecond          uint64
	pprofPrefix               string
	sendErrorFrames           bool
	serviceName               string
	environment               string
	uploadSymbolQueryInterval time.Duration
	uploadSymbols             bool
	uploadDynamicSymbols      bool
	uploadGoPCLnTab           bool
	uploadSymbolsDryRun       bool
	tags                      string
	timeline                  bool
	tracers                   string
	verboseMode               bool
	verboseeBPF               bool
	apiKey                    string
	appKey                    string
	site                      string
	additionalSymbolEndpoints []reporter.SymbolEndpoint
	agentless                 bool
	enableGoRuntimeProfiler   bool
	cmd                       *cli.Command
}

func parseArgs() (*arguments, error) {
	var args arguments
	versionInfo := version.GetVersionInfo()

	cli.VersionPrinter = func(_ *cli.Command) {
		fmt.Printf("dd-otel-host-profiler, version v%s (revision: %s, date: %s), arch: %v\n",
			versionInfo.Version, versionInfo.VcsRevision, versionInfo.VcsTime, runtime.GOARCH)
	}

	cli.VersionFlag = &cli.BoolFlag{
		Name:  "version",
		Usage: "print the version",
	}

	app := cli.Command{
		Name:      "dd-otel-host-profiler",
		Usage:     "Datadog OpenTelemetry host profiler",
		Copyright: copyright,
		Version:   versionInfo.Version,
		Flags: []cli.Flag{
			&cli.UintFlag{
				Name:        "bpf-log-level",
				Value:       0,
				Usage:       "Log level of the eBPF verifier output (0,1,2).",
				Destination: &args.bpfVerifierLogLevel,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_BPF_LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:        "agent-url",
				Aliases:     []string{"U"},
				Value:       defaultArgAgentURL,
				Usage:       "The Datadog trace agent URL in the format of http://host:port.",
				Destination: &args.agentURL,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TRACE_AGENT_URL", "DD_TRACE_AGENT_URL"),
			},
			&cli.StringFlag{
				Name:        "service",
				Aliases:     []string{"S"},
				Value:       "dd-otel-host-profiler",
				Usage:       "Service name.",
				Destination: &args.serviceName,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SERVICE", "DD_SERVICE"),
			},
			&cli.StringFlag{
				Name:        "environment",
				Aliases:     []string{"E"},
				Usage:       "The name of the environment to use in the Datadog UI.",
				Destination: &args.environment,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_ENV", "DD_ENV"),
			},
			&cli.StringFlag{
				Name:        "tags",
				Usage:       "User-specified tags separated by ',': key1:value1,key2:value2.",
				Destination: &args.tags,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TAGS", "DD_TAGS"),
			},
			&cli.UintFlag{
				Name:  "map-scale-factor",
				Value: defaultArgMapScaleFactor,
				Usage: fmt.Sprintf("Scaling factor for eBPF map sizes. "+
					"Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. "+
					"Default is %d corresponding to 4GB of executable address space, max is %d.",
					defaultArgMapScaleFactor, maxArgMapScaleFactor),
				Destination: &args.mapScaleFactor,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_MAP_SCALE_FACTOR"),
			},
			&cli.DurationFlag{
				Name:        "monitor-interval",
				Value:       defaultArgMonitorInterval,
				Usage:       "Set the monitor interval in seconds.",
				Destination: &args.monitorInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_MONITOR_INTERVAL"),
			},
			&cli.DurationFlag{
				Name:  "clock-sync-interval",
				Value: defaultClockSyncInterval,
				Usage: "Set the sync interval with the realtime clock. " +
					"If zero, monotonic-realtime clock sync will be performed once, " +
					"on agent startup, but not periodically.",
				Destination: &args.clockSyncInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_CLOCK_SYNC_INTERVAL"),
			},
			&cli.BoolFlag{
				Name:  "no-kernel-version-check",
				Value: false,
				Usage: "Disable checking kernel version for eBPF support. " +
					"Use at your own risk, to run the agent on older kernels with backported eBPF features.",
				Destination: &args.noKernelVersionCheck,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_NO_KERNEL_VERSION_CHECK"),
			},
			&cli.DurationFlag{
				Name:        "probabilistic-interval",
				Value:       defaultProbabilisticInterval,
				Usage:       "Time interval for which probabilistic profiling will be enabled or disabled.",
				Destination: &args.probabilisticInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_PROBABILISTIC_INTERVAL"),
			},
			&cli.UintFlag{
				Name:  "probabilistic-threshold",
				Value: defaultProbabilisticThreshold,
				Usage: fmt.Sprintf("If set to a value between 1 and %d will enable probabilistic profiling: "+
					"every probabilistic-interval a random number between 0 and %d is chosen. "+
					"If the given probabilistic-threshold is greater than this "+
					"random number, the agent will collect profiles from this system for the duration of the interval.",
					tracer.ProbabilisticThresholdMax-1, tracer.ProbabilisticThresholdMax-1),
				Destination: &args.probabilisticThreshold,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_PROBABILISTIC_THRESHOLD"),
			},
			&cli.DurationFlag{
				Name:        "upload-period",
				Value:       defaultArgReporterInterval,
				Usage:       "Set the reporter's interval in seconds.",
				Destination: &args.reporterInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_UPLOAD_PERIOD"),
			},
			&cli.UintFlag{
				Name:        "sampling-rate",
				Value:       defaultArgSamplesPerSecond,
				Usage:       "Set the frequency (in Hz) of stack trace sampling.",
				Destination: &args.samplesPerSecond,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SAMPLING_RATE"),
			},
			&cli.BoolFlag{
				Name:        "timeline",
				Value:       false,
				Usage:       "Enable timeline feature.",
				Destination: &args.timeline,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TIMELINE_ENABLED"),
			},
			&cli.BoolFlag{
				Name:        "send-error-frames",
				Value:       defaultArgSendErrorFrames,
				Usage:       "Send error frames",
				Destination: &args.sendErrorFrames,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SEND_ERROR_FRAMES"),
			},
			&cli.StringFlag{
				Name:        "tracers",
				Aliases:     []string{"t"},
				Value:       "all",
				Usage:       "Comma-separated list of interpreter tracers to include.",
				Destination: &args.tracers,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TRACERS"),
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Value:       false,
				Usage:       "Enable verbose logging and debugging capabilities.",
				Destination: &args.verboseMode,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_VERBOSE"),
			},
			&cli.BoolFlag{
				Name:        "verbose-ebpf",
				Value:       false,
				Usage:       "Enable verbose logging and debugging capabilities for eBPF.",
				Destination: &args.verboseeBPF,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_VERBOSE_EBPF"),
			},
			&cli.StringFlag{
				Name:        "pprof-prefix",
				Usage:       "Dump pprof profile to `FILE`.",
				Destination: &args.pprofPrefix,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_PPROF_PREFIX"),
			},
			&cli.StringFlag{
				Name: "node",
				Usage: "The name of the node that the profiler is running on. " +
					"If on Kubernetes, this must match the Kubernetes node name.",
				Destination: &args.node,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_NODE"),
			},
			&cli.BoolFlag{
				Name:        "upload-symbols",
				Value:       false,
				Usage:       "Enable local symbol upload.",
				Hidden:      true,
				Destination: &args.uploadSymbols,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_EXPERIMENTAL_UPLOAD_SYMBOLS"),
			},
			&cli.BoolFlag{
				Name:        "upload-dynamic-symbols",
				Usage:       "Enable dynamic symbols upload.",
				Value:       true,
				Hidden:      true,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_EXPERIMENTAL_UPLOAD_DYNAMIC_SYMBOLS"),
				Destination: &args.uploadDynamicSymbols,
			},
			&cli.BoolFlag{
				Name:        "upload-gopclntab",
				Usage:       "Enable gopcnltab upload.",
				Value:       false,
				Hidden:      true,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_EXPERIMENTAL_UPLOAD_GOPCLNTAB"),
				Destination: &args.uploadGoPCLnTab,
			},
			&cli.BoolFlag{
				Name:        "upload-symbols-dry-run",
				Value:       false,
				Usage:       "Local symbol upload dry-run.",
				Hidden:      true,
				Destination: &args.uploadSymbolsDryRun,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_EXPERIMENTAL_UPLOAD_SYMBOLS_DRY_RUN"),
			},
			&cli.StringFlag{
				Name:        "api-key",
				Usage:       "Datadog API key.",
				Hidden:      true,
				Destination: &args.apiKey,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_API_KEY", "DD_API_KEY"),
				Validator: func(s string) error {
					if s == "" || isAPIKeyValid(s) {
						return nil
					}
					return errors.New("API key is not valid")
				},
			},
			&cli.StringFlag{
				Name:        "app-key",
				Usage:       "Datadog APP key.",
				Hidden:      true,
				Destination: &args.appKey,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_APP_KEY", "DD_APP_KEY"),
				Validator: func(s string) error {
					if s == "" || isAPPKeyValid(s) {
						return nil
					}
					return errors.New("APP key is not valid")
				},
			},
			&cli.StringFlag{
				Name:        "site",
				Value:       "datadoghq.com",
				Usage:       "Datadog site.",
				Hidden:      true,
				Destination: &args.site,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SITE", "DD_SITE"),
			},
			&cli.StringFlag{
				Name:   "additional-symbol-endpoints",
				Usage:  "Additional endpoints to upload symbols to.",
				Hidden: true,
				// This is required by urfave/cli in order to run the Action when
				// this flag is defined outside of the command-line arguments.
				Local:   true,
				Sources: cli.EnvVars("DD_HOST_PROFILING_ADDITIONAL_SYMBOL_ENDPOINTS"),
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if s == "" {
						return nil
					}
					err := json.Unmarshal([]byte(s), &args.additionalSymbolEndpoints)
					if err != nil {
						return errors.New("error parsing DD_HOST_PROFILING_ADDITIONAL_SYMBOL_ENDPOINTS: invalid JSON")
					}
					for _, e := range args.additionalSymbolEndpoints {
						if e.Site == "" || e.APIKey == "" || e.AppKey == "" {
							return errors.New("error parsing DD_HOST_PROFILING_ADDITIONAL_SYMBOL_ENDPOINTS: site, api key and app key should all be set and non-empty strings")
						}
						if !isAPIKeyValid(e.APIKey) {
							return fmt.Errorf("error parsing DD_HOST_PROFILING_ADDITIONAL_SYMBOL_ENDPOINTS: API key for site %s is not valid", e.Site)
						}
						if !isAPPKeyValid(e.AppKey) {
							return fmt.Errorf("error parsing DD_HOST_PROFILING_ADDITIONAL_SYMBOL_ENDPOINTS: app key for site %s is not valid", e.Site)
						}
					}
					return nil
				},
			},
			&cli.BoolFlag{
				Name:        "profile",
				Value:       false,
				Usage:       "Enable self-profiling with Go runtime profiler.",
				Destination: &args.enableGoRuntimeProfiler,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_RUNTIME_PROFILER"),
			},
			&cli.DurationFlag{
				Name:        "symbol-query-interval",
				Value:       defaultSymbolQueryInterval,
				Hidden:      true,
				Usage:       "Symbol query period (queries during a period are batched, 0 means no batching).",
				Destination: &args.uploadSymbolQueryInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SYMBOL_QUERY_PERIOD"),
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			args.cmd = cmd
			return nil
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		return nil, err
	}

	if args.cmd == nil {
		return nil, nil
	}
	return &args, nil
}

func (args *arguments) dump() {
	log.Debug("Config:")
	for _, f := range args.cmd.Flags {
		setStr := "default"
		if args.cmd.IsSet(f.Names()[0]) {
			setStr = "set"
		}
		log.Debugf("%s: \"%v\" [%s]", f.Names()[0], args.cmd.Value(f.Names()[0]), setStr)
	}
}
