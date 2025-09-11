// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"go.opentelemetry.io/ebpf-profiler/tracer"

	"github.com/DataDog/dd-otel-host-profiler/version"
)

// Short Copyright / license text for eBPF code
const Copyright = `Copyright 2024 Datadog, Inc.

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
	MaxArgMapScaleFactor = 8
)

type Arguments struct {
	Config
	Copyright   bool
	VerboseMode bool
	cmd         *cli.Command
}

func ParseArgs() (*Arguments, error) {
	return parseCLIArgs(os.Args)
}

func parseCLIArgs(osArgs []string) (*Arguments, error) {
	var args Arguments
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
		Copyright: Copyright,
		Version:   versionInfo.Version,
		Flags: []cli.Flag{
			&cli.UintFlag{
				Name:        "bpf-log-level",
				Value:       0,
				Usage:       "Log level of the eBPF verifier output (0,1,2).",
				Destination: &args.BPFVerifierLogLevel,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_BPF_LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:        "agent-url",
				Aliases:     []string{"U"},
				Value:       defaultArgAgentURL,
				Usage:       "The Datadog trace agent URL in the format of http://host:port.",
				Destination: &args.AgentURL,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TRACE_AGENT_URL", "DD_TRACE_AGENT_URL"),
			},
			&cli.StringFlag{
				Name:        "host-service",
				Usage:       "Host service name when split by service is disabled",
				Destination: &args.HostServiceName,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SERVICE"),
			},
			&cli.StringFlag{
				Name:        "environment",
				Aliases:     []string{"E"},
				Usage:       "The name of the environment to use in the Datadog UI.",
				Destination: &args.Environment,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_ENV", "DD_ENV"),
			},
			&cli.StringFlag{
				Name:        "tags",
				Usage:       "User-specified tags separated by ',': key1:value1,key2:value2.",
				Destination: &args.Tags,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TAGS", "DD_TAGS"),
			},
			&cli.UintFlag{
				Name:  "map-scale-factor",
				Value: defaultArgMapScaleFactor,
				Usage: fmt.Sprintf("Scaling factor for eBPF map sizes. "+
					"Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. "+
					"Default is %d corresponding to 4GB of executable address space, max is %d.",
					defaultArgMapScaleFactor, MaxArgMapScaleFactor),
				Destination: &args.MapScaleFactor,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_MAP_SCALE_FACTOR"),
			},
			&cli.DurationFlag{
				Name:        "monitor-interval",
				Value:       defaultArgMonitorInterval,
				Usage:       "Set the monitor interval in seconds.",
				Destination: &args.MonitorInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_MONITOR_INTERVAL"),
			},
			&cli.DurationFlag{
				Name:  "clock-sync-interval",
				Value: defaultClockSyncInterval,
				Usage: "Set the sync interval with the realtime clock. " +
					"If zero, monotonic-realtime clock sync will be performed once, " +
					"on agent startup, but not periodically.",
				Destination: &args.ClockSyncInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_CLOCK_SYNC_INTERVAL"),
			},
			&cli.BoolFlag{
				Name:  "no-kernel-version-check",
				Value: false,
				Usage: "Disable checking kernel version for eBPF support. " +
					"Use at your own risk, to run the agent on older kernels with backported eBPF features.",
				Destination: &args.NoKernelVersionCheck,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_NO_KERNEL_VERSION_CHECK"),
			},
			&cli.DurationFlag{
				Name:        "probabilistic-interval",
				Value:       defaultProbabilisticInterval,
				Usage:       "Time interval for which probabilistic profiling will be enabled or disabled.",
				Destination: &args.ProbabilisticInterval,
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
				Destination: &args.ProbabilisticThreshold,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_PROBABILISTIC_THRESHOLD"),
			},
			&cli.DurationFlag{
				Name:        "upload-period",
				Value:       defaultArgReporterInterval,
				Usage:       "Set the reporter's interval in seconds.",
				Destination: &args.ReporterInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_UPLOAD_PERIOD"),
			},
			&cli.UintFlag{
				Name:        "sampling-rate",
				Value:       defaultArgSamplesPerSecond,
				Usage:       "Set the frequency (in Hz) of stack trace sampling.",
				Destination: &args.SamplesPerSecond,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SAMPLING_RATE"),
			},
			&cli.BoolFlag{
				Name:        "timeline",
				Value:       false,
				Usage:       "Enable timeline feature.",
				Destination: &args.Timeline,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TIMELINE_ENABLED"),
			},
			&cli.BoolFlag{
				Name:        "send-error-frames",
				Value:       defaultArgSendErrorFrames,
				Usage:       "Send error frames",
				Destination: &args.SendErrorFrames,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SEND_ERROR_FRAMES"),
			},
			&cli.StringFlag{
				Name:        "tracers",
				Aliases:     []string{"t"},
				Value:       "all",
				Usage:       "Comma-separated list of interpreter tracers to include.",
				Destination: &args.Tracers,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_TRACERS"),
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Value:       false,
				Usage:       "Enable verbose logging and debugging capabilities.",
				Destination: &args.VerboseMode,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_VERBOSE"),
			},
			&cli.BoolFlag{
				Name:        "verbose-ebpf",
				Value:       false,
				Usage:       "Enable verbose logging and debugging capabilities for eBPF.",
				Destination: &args.VerboseeBPF,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_VERBOSE_EBPF"),
			},
			&cli.StringFlag{
				Name:        "pprof-prefix",
				Usage:       "Dump pprof profile to `FILE`.",
				Destination: &args.PprofPrefix,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_PPROF_PREFIX"),
			},
			&cli.StringFlag{
				Name: "node",
				Usage: "The name of the node that the profiler is running on. " +
					"If on Kubernetes, this must match the Kubernetes node name.",
				Destination: &args.Node,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_NODE"),
			},
			&cli.BoolFlag{
				Name:        "upload-symbols",
				Value:       true,
				Usage:       "Enable local symbol upload.",
				Hidden:      true,
				Destination: &args.UploadSymbols,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_UPLOAD_SYMBOLS"),
			},
			&cli.BoolFlag{
				Name:        "upload-dynamic-symbols",
				Usage:       "Enable dynamic symbols upload.",
				Value:       false,
				Hidden:      true,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_UPLOAD_DYNAMIC_SYMBOLS"),
				Destination: &args.UploadDynamicSymbols,
			},
			&cli.BoolFlag{
				Name:        "upload-gopclntab",
				Usage:       "Enable gopcnltab upload.",
				Value:       true,
				Hidden:      true,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_UPLOAD_GOPCLNTAB"),
				Destination: &args.UploadGoPCLnTab,
			},
			&cli.BoolFlag{
				Name:        "upload-symbols-dry-run",
				Value:       false,
				Usage:       "Local symbol upload dry-run.",
				Hidden:      true,
				Destination: &args.UploadSymbolsDryRun,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_UPLOAD_SYMBOLS_DRY_RUN"),
			},
			&cli.StringFlag{
				Name:        "api-key",
				Usage:       "Datadog API key.",
				Hidden:      true,
				Destination: &args.APIKey,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_API_KEY", "DD_API_KEY"),
				Validator: func(s string) error {
					if s == "" || IsAPIKeyValid(s) {
						return nil
					}
					return errors.New("API key is not valid")
				},
			},
			&cli.StringFlag{
				Name:        "app-key",
				Usage:       "Datadog APP key.",
				Hidden:      true,
				Destination: &args.AppKey,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_APP_KEY", "DD_APP_KEY"),
				Validator: func(s string) error {
					if s == "" || IsAPPKeyValid(s) {
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
				Destination: &args.Site,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SITE", "DD_SITE"),
			},
			&cli.GenericFlag{
				Name:    "additional-symbol-endpoints",
				Usage:   "Additional endpoints to upload symbols to.",
				Hidden:  true,
				Sources: cli.EnvVars("DD_HOST_PROFILING_ADDITIONAL_SYMBOL_ENDPOINTS"),
				Value:   &args.AdditionalSymbolEndpoints,
			},
			&cli.BoolFlag{
				Name:        "profile",
				Value:       false,
				Usage:       "Enable self-profiling with the Go runtime profiler.",
				Destination: &args.EnableGoRuntimeProfiler,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_RUNTIME_PROFILER"),
			},
			&cli.DurationFlag{
				Name:        "runtime-profile-period",
				Hidden:      true,
				Usage:       "Set the period for self-profiling with the Go runtime profiler. Only used if --profile is enabled.",
				Destination: &args.GoRuntimeProfilerPeriod,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_RUNTIME_PROFILER_PERIOD"),
			},
			&cli.StringFlag{
				Name:        "runtime-metrics-statsd-address",
				Usage:       "If set, enables Go runtime metrics collection and sends them to the given StatsD address.",
				Hidden:      true,
				Destination: &args.GoRuntimeMetricsStatsdAddress,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_RUNTIME_METRICS_STATSD_ADDRESS"),
			},
			&cli.DurationFlag{
				Name:        "symbol-query-interval",
				Value:       defaultSymbolQueryInterval,
				Hidden:      true,
				Usage:       "Symbol query interval (queries during a period are batched, 0 means no batching).",
				Destination: &args.UploadSymbolQueryInterval,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SYMBOL_QUERY_INTERVAL"),
			},
			&cli.BoolFlag{
				Name:        "split-by-service",
				Value:       true,
				Usage:       "Split profiles by service.",
				Destination: &args.EnableSplitByService,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SPLIT_BY_SERVICE"),
			},
			&cli.StringFlag{
				Name:        "split-by-service-suffix",
				Value:       "",
				Usage:       "Suffix to add to service name in profiles when split-by-service is enabled.",
				Destination: &args.SplitServiceSuffix,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_SPLIT_SERVICE_SUFFIX"),
			},
			&cli.BoolFlag{
				Name:        "upload-symbols-http2",
				Value:       false, // HTTP/2 is disabled by default, since support in the backend is recent
				Hidden:      true,
				Usage:       "Use HTTP/2 when available for symbol upload. Only used if upload-symbols is enabled.",
				Destination: &args.UploadSymbolsHTTP2,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_UPLOAD_SYMBOLS_HTTP2"),
			},
			&cli.BoolFlag{
				Name: "collect-context",
				// TODO: switch info log to debug log in reporter code once context collection is enabled by default
				Value:       false,
				Hidden:      true,
				Usage:       "Enable context collection.",
				Destination: &args.CollectContext,
				Sources:     cli.EnvVars("DD_HOST_PROFILING_COLLECT_CONTEXT"),
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			args.cmd = cmd
			return nil
		},
	}

	if err := app.Run(context.Background(), osArgs); err != nil {
		return nil, err
	}

	if args.cmd == nil {
		return nil, nil
	}

	return &args, nil
}

func (args *Arguments) Dump() {
	log.Debug("Config:")
	for _, f := range args.cmd.Flags {
		setStr := "default"
		if args.cmd.IsSet(f.Names()[0]) {
			setStr = "set"
		}
		log.Debugf("%s: \"%v\" [%s]", f.Names()[0], args.cmd.Value(f.Names()[0]), setStr)
	}
}

func CreateConfig() (*Config, error) {
	args, err := parseCLIArgs(nil)
	if err != nil {
		return nil, err
	}
	return &args.Config, nil
}
