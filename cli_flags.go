// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/DataDog/dd-otel-host-profiler/version"
	cebpf "github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer"
)

const (
	// Default values for CLI flags
	defaultArgSamplesPerSecond    = 20
	defaultArgReporterInterval    = 5.0 * time.Second
	defaultArgMonitorInterval     = 5.0 * time.Second
	defaultClockSyncInterval      = 3 * time.Minute
	defaultProbabilisticThreshold = tracer.ProbabilisticThresholdMax
	defaultProbabilisticInterval  = 1 * time.Minute
	defaultArgSendErrorFrames     = false
	defaultArgCollAgentAddr       = "http://localhost:8126"

	// This is the X in 2^(n + x) where n is the default hardcoded map size value
	defaultArgMapScaleFactor = 0
	// 1TB of executable address space
	maxArgMapScaleFactor = 8
)

type arguments struct {
	bpfVerifierLogLevel    uint64
	bpfVerifierLogSize     uint64
	collAgentAddr          string
	copyright              bool
	mapScaleFactor         uint64
	monitorInterval        time.Duration
	clockSyncInterval      time.Duration
	noKernelVersionCheck   bool
	node                   string
	probabilisticInterval  time.Duration
	probabilisticThreshold uint64
	reporterInterval       time.Duration
	samplesPerSecond       uint64
	cpuProfileDump         string
	sendErrorFrames        bool
	serviceName            string
	serviceVersion         string
	environment            string
	uploadSymbols          bool
	uploadDynamicSymbols   bool
	uploadSymbolsDryRun    bool
	tags                   string
	timeline               bool
	tracers                string
	verboseMode            bool
	apiKey                 string
	appKey                 string
	site                   string
	agentless              bool
	cmd                    *cli.Command
}

func AddDefaultEnvVar[T any, C any, VC cli.ValueCreator[T, C]](flag *cli.FlagBase[T, C, VC], experimental bool) *cli.FlagBase[T, C, VC] {
	prefix := "DD_PROFILING_"
	if experimental {
		prefix += "EXPERIMENTAL_"
	}
	name := strings.Replace(strings.ToUpper(flag.Name), "-", "_", -1)
	flag.Sources.Append(cli.EnvVars(prefix + name))
	return flag
}

func parseArgs() (*arguments, error) {
	var args arguments
	versionInfo := version.GetVersionInfo()

	cli.VersionPrinter = func(_ *cli.Command) {
		fmt.Printf("dd-otel-host-profiler, version %s (revision: %s, date: %s), arch: %v\n",
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
			AddDefaultEnvVar(&cli.UintFlag{
				Name:        "bpf-log-level",
				Value:       0,
				Usage:       "Log level of the eBPF verifier output (0,1,2).",
				Destination: &args.bpfVerifierLogLevel,
			}, false),
			AddDefaultEnvVar(&cli.UintFlag{
				Name:  "bpf-log-size",
				Value: cebpf.DefaultVerifierLogSize,
				Usage: "Size in bytes that will be allocated for the eBPF verifier output. " +
					"Only takes effect if bpf-log-level > 0.",
				Destination: &args.bpfVerifierLogSize,
			}, false),
			&cli.StringFlag{
				Name:        "url",
				Aliases:     []string{"U"},
				Value:       defaultArgCollAgentAddr,
				Usage:       "The Datadog agent URL in the format of http://host:port.",
				Sources:     cli.EnvVars("DD_TRACE_AGENT_URL"),
				Destination: &args.collAgentAddr,
			},
			&cli.StringFlag{
				Name:        "service",
				Aliases:     []string{"S"},
				Usage:       "Service name.",
				Sources:     cli.EnvVars("DD_SERVICE"),
				Destination: &args.serviceName,
			},
			&cli.StringFlag{
				Name:        "environment",
				Aliases:     []string{"E"},
				Value:       "dd-otel-host-profiler",
				Usage:       "The name of the environment to use in the Datadog UI.",
				Sources:     cli.EnvVars("DD_ENV"),
				Destination: &args.environment,
			},
			&cli.StringFlag{
				Name:        "service-version",
				Aliases:     []string{"V"},
				Usage:       "Version of the service being profiled.",
				Destination: &args.serviceVersion,
				Sources:     cli.EnvVars("DD_VERSION"),
			},
			&cli.StringFlag{
				Name:        "tags",
				Usage:       "User-specified tags separated by ',': key1:value1,key2:value2.",
				Sources:     cli.EnvVars("DD_TAGS"),
				Destination: &args.tags,
			},
			AddDefaultEnvVar(
				&cli.UintFlag{
					Name:  "map-scale-factor",
					Value: defaultArgMapScaleFactor,
					Usage: fmt.Sprintf("Scaling factor for eBPF map sizes. "+
						"Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. "+
						"Default is %d corresponding to 4GB of executable address space, max is %d.",
						defaultArgMapScaleFactor, maxArgMapScaleFactor),
					Destination: &args.mapScaleFactor,
				}, false),
			AddDefaultEnvVar(&cli.DurationFlag{
				Name:        "monitor-interval",
				Value:       defaultArgMonitorInterval,
				Usage:       "Set the monitor interval in seconds.",
				Destination: &args.monitorInterval,
			}, false),
			AddDefaultEnvVar(&cli.DurationFlag{
				Name:  "clock-sync-interval",
				Value: defaultClockSyncInterval,
				Usage: "Set the sync interval with the realtime clock. " +
					"If zero, monotonic-realtime clock sync will be performed once, " +
					"on agent startup, but not periodically.",
				Destination: &args.clockSyncInterval,
			}, false),
			AddDefaultEnvVar(&cli.BoolFlag{
				Name:  "no-kernel-version-check",
				Value: false,
				Usage: "Disable checking kernel version for eBPF support. " +
					"Use at your own risk, to run the agent on older kernels with backported eBPF features.",
				Destination: &args.noKernelVersionCheck,
			}, false),
			&cli.DurationFlag{
				Name:        "probabilistic-interval",
				Value:       defaultProbabilisticInterval,
				Usage:       "Time interval for which probabilistic profiling will be enabled or disabled.",
				Destination: &args.probabilisticInterval,
			},
			AddDefaultEnvVar(&cli.UintFlag{
				Name:  "probabilistic-threshold",
				Value: defaultProbabilisticThreshold,
				Usage: fmt.Sprintf("If set to a value between 1 and %d will enable probabilistic profiling: "+
					"every probabilistic-interval a random number between 0 and %d is chosen. "+
					"If the given probabilistic-threshold is greater than this "+
					"random number, the agent will collect profiles from this system for the duration of the interval.",
					tracer.ProbabilisticThresholdMax-1, tracer.ProbabilisticThresholdMax-1),
				Destination: &args.probabilisticThreshold,
			}, false),
			AddDefaultEnvVar(&cli.DurationFlag{
				Name:        "upload-period",
				Value:       defaultArgReporterInterval,
				Usage:       "Set the reporter's interval in seconds.",
				Destination: &args.reporterInterval,
			}, false),
			AddDefaultEnvVar(&cli.UintFlag{
				Name:        "rate",
				Value:       defaultArgSamplesPerSecond,
				Usage:       "Set the frequency (in Hz) of stack trace sampling.",
				Destination: &args.samplesPerSecond,
			}, false),
			&cli.BoolFlag{
				Name:        "timeline",
				Value:       false,
				Usage:       "Enable timeline feature.",
				Destination: &args.timeline,
				Sources:     cli.EnvVars("DD_PROFILING_TIMELINE_ENABLED"),
			},
			AddDefaultEnvVar(&cli.BoolFlag{
				Name:        "send-error-frames",
				Value:       defaultArgSendErrorFrames,
				Usage:       "Send error frames",
				Destination: &args.sendErrorFrames,
			}, false),
			AddDefaultEnvVar(&cli.StringFlag{
				Name:        "tracers",
				Aliases:     []string{"t"},
				Value:       "all",
				Usage:       "Comma-separated list of interpreter tracers to include.",
				Destination: &args.tracers,
			}, false),
			AddDefaultEnvVar(&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Value:       false,
				Usage:       "Enable verbose logging and debugging capabilities.",
				Destination: &args.verboseMode,
			}, false),
			AddDefaultEnvVar(&cli.StringFlag{
				Name:        "dump-cpuprofile",
				Usage:       "Dump CPU pprof profile to `FILE`.",
				Destination: &args.cpuProfileDump,
			}, false),
			AddDefaultEnvVar(&cli.StringFlag{
				Name: "node",
				Usage: "The name of the node that the profiler is running on. " +
					"If on Kubernetes, this must match the Kubernetes node name.",
				Destination: &args.node,
			}, false),
			AddDefaultEnvVar(&cli.BoolFlag{
				Name:        "upload-symbols",
				Value:       false,
				Usage:       "Enable local symbol upload.",
				Hidden:      true,
				Destination: &args.uploadSymbols,
			}, true),
			&cli.BoolWithInverseFlag{
				BoolFlag: AddDefaultEnvVar(&cli.BoolFlag{
					Name:  "upload-dynamic-symbols",
					Usage: "Enable dynamic symbols upload.",
					// Cannot set default value to true because it fails at runtime with:
					// "Failure to parse arguments: cannot set both flags `--upload-dynamic-symbols` and `--no-upload-dynamic-symbols`"
					// Value:       true,
					DefaultText: "true",
					Hidden:      true,
				}, true),
			},
			AddDefaultEnvVar(&cli.BoolFlag{
				Name:        "upload-symbols-dry-run",
				Value:       false,
				Usage:       "Local symbol upload dry-run.",
				Hidden:      true,
				Destination: &args.uploadSymbolsDryRun,
			}, true),
			&cli.StringFlag{
				Name:        "api-key",
				Usage:       "Datadog API key.",
				Hidden:      true,
				Sources:     cli.EnvVars("DD_API_KEY"),
				Destination: &args.apiKey,
				Validator: func(s string) error {
					if s == "" || isAPIKeyValid(s) {
						return nil
					}
					return fmt.Errorf("API key is not valid")
				},
			},
			&cli.StringFlag{
				Name:        "app-key",
				Usage:       "Datadog APP key.",
				Hidden:      true,
				Sources:     cli.EnvVars("DD_APP_KEY"),
				Destination: &args.appKey,
				Validator: func(s string) error {
					if s == "" || isAPPKeyValid(s) {
						return nil
					}
					return fmt.Errorf("APP key is not valid")
				},
			},
			&cli.StringFlag{
				Name:        "dd-site",
				Value:       "datadoghq.com",
				Usage:       "Datadog site.",
				Hidden:      true,
				Sources:     cli.EnvVars("DD_SITE"),
				Destination: &args.site,
			},
			AddDefaultEnvVar(&cli.BoolFlag{
				Name:        "agentless",
				Value:       false,
				Usage:       "Run the profiler in agentless mode.",
				Hidden:      true,
				Destination: &args.agentless,
			}, false),
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.IsSet("upload-dynamic-symbols") {
				args.uploadDynamicSymbols = cmd.Bool("upload-dynamic-symbols")
			} else {
				cmd.Set("upload-dynamic-symbols", "true")
				args.uploadDynamicSymbols = true
			}
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
