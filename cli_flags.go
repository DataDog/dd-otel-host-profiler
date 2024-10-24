// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"context"
	"errors"
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

type envVarType int

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

const (
	shortEnvVar = envVarType(iota)
	longEnvVar
	experimentalEnvVar
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
	pprofPrefix            string
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

func addDefaultEnvVarWithName[T any, C any, VC cli.ValueCreator[T, C]](flag *cli.FlagBase[T, C, VC],
	envVarType envVarType, name string) *cli.FlagBase[T, C, VC] {
	const otelProfilerPrefix = "DD_HOST_"
	var prefix string
	switch envVarType {
	case shortEnvVar:
		prefix = ""
	case longEnvVar:
		prefix = "PROFILING_"
	case experimentalEnvVar:
		prefix = "PROFILING_EXPERIMENTAL_"
	}

	envVarName := "DD_" + prefix + name
	prefixedEnvvarName := otelProfilerPrefix + prefix + name

	flag.Sources.Append(cli.EnvVars(prefixedEnvvarName, envVarName))
	return flag
}

func addDefaultEnvVar[T any, C any, VC cli.ValueCreator[T, C]](flag *cli.FlagBase[T, C, VC],
	envVarType envVarType) *cli.FlagBase[T, C, VC] {
	name := strings.ReplaceAll(strings.ToUpper(flag.Name), "-", "_")
	return addDefaultEnvVarWithName(flag, envVarType, name)
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
			addDefaultEnvVar(
				&cli.UintFlag{
					Name:        "bpf-log-level",
					Value:       0,
					Usage:       "Log level of the eBPF verifier output (0,1,2).",
					Destination: &args.bpfVerifierLogLevel,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.UintFlag{
					Name:  "bpf-log-size",
					Value: cebpf.DefaultVerifierLogSize,
					Usage: "Size in bytes that will be allocated for the eBPF verifier output. " +
						"Only takes effect if bpf-log-level > 0.",
					Destination: &args.bpfVerifierLogSize,
				}, longEnvVar),
			addDefaultEnvVarWithName(
				&cli.StringFlag{
					Name:        "agent-url",
					Aliases:     []string{"U"},
					Value:       defaultArgCollAgentAddr,
					Usage:       "The Datadog agent URL in the format of http://host:port.",
					Destination: &args.collAgentAddr,
				}, shortEnvVar, "TRACE_AGENT_URL"),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name:        "service",
					Aliases:     []string{"S"},
					Usage:       "Service name.",
					Destination: &args.serviceName,
				}, shortEnvVar),
			addDefaultEnvVarWithName(
				&cli.StringFlag{
					Name:        "environment",
					Aliases:     []string{"E"},
					Value:       "dd-otel-host-profiler",
					Usage:       "The name of the environment to use in the Datadog UI.",
					Destination: &args.environment,
				}, shortEnvVar, "ENV"),
			addDefaultEnvVarWithName(
				&cli.StringFlag{
					Name:        "service-version",
					Aliases:     []string{"V"},
					Usage:       "Version of the service being profiled.",
					Destination: &args.serviceVersion,
				}, shortEnvVar, "VERSION"),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name:        "tags",
					Usage:       "User-specified tags separated by ',': key1:value1,key2:value2.",
					Destination: &args.tags,
				}, shortEnvVar),
			addDefaultEnvVar(
				&cli.UintFlag{
					Name:  "map-scale-factor",
					Value: defaultArgMapScaleFactor,
					Usage: fmt.Sprintf("Scaling factor for eBPF map sizes. "+
						"Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. "+
						"Default is %d corresponding to 4GB of executable address space, max is %d.",
						defaultArgMapScaleFactor, maxArgMapScaleFactor),
					Destination: &args.mapScaleFactor,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.DurationFlag{
					Name:        "monitor-interval",
					Value:       defaultArgMonitorInterval,
					Usage:       "Set the monitor interval in seconds.",
					Destination: &args.monitorInterval,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.DurationFlag{
					Name:  "clock-sync-interval",
					Value: defaultClockSyncInterval,
					Usage: "Set the sync interval with the realtime clock. " +
						"If zero, monotonic-realtime clock sync will be performed once, " +
						"on agent startup, but not periodically.",
					Destination: &args.clockSyncInterval,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.BoolFlag{
					Name:  "no-kernel-version-check",
					Value: false,
					Usage: "Disable checking kernel version for eBPF support. " +
						"Use at your own risk, to run the agent on older kernels with backported eBPF features.",
					Destination: &args.noKernelVersionCheck,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.DurationFlag{
					Name:        "probabilistic-interval",
					Value:       defaultProbabilisticInterval,
					Usage:       "Time interval for which probabilistic profiling will be enabled or disabled.",
					Destination: &args.probabilisticInterval,
				}, longEnvVar),
			addDefaultEnvVar(&cli.UintFlag{
				Name:  "probabilistic-threshold",
				Value: defaultProbabilisticThreshold,
				Usage: fmt.Sprintf("If set to a value between 1 and %d will enable probabilistic profiling: "+
					"every probabilistic-interval a random number between 0 and %d is chosen. "+
					"If the given probabilistic-threshold is greater than this "+
					"random number, the agent will collect profiles from this system for the duration of the interval.",
					tracer.ProbabilisticThresholdMax-1, tracer.ProbabilisticThresholdMax-1),
				Destination: &args.probabilisticThreshold,
			}, longEnvVar),
			addDefaultEnvVar(&cli.DurationFlag{
				Name:        "upload-period",
				Value:       defaultArgReporterInterval,
				Usage:       "Set the reporter's interval in seconds.",
				Destination: &args.reporterInterval,
			}, longEnvVar),
			addDefaultEnvVar(&cli.UintFlag{
				Name:        "sampling-rate",
				Value:       defaultArgSamplesPerSecond,
				Usage:       "Set the frequency (in Hz) of stack trace sampling.",
				Destination: &args.samplesPerSecond,
			}, longEnvVar),
			addDefaultEnvVarWithName(
				&cli.BoolFlag{
					Name:        "timeline",
					Value:       false,
					Usage:       "Enable timeline feature.",
					Destination: &args.timeline,
				}, longEnvVar, "TIMELINE_ENABLED"),
			addDefaultEnvVar(
				&cli.BoolFlag{
					Name:        "send-error-frames",
					Value:       defaultArgSendErrorFrames,
					Usage:       "Send error frames",
					Destination: &args.sendErrorFrames,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name:        "tracers",
					Aliases:     []string{"t"},
					Value:       "all",
					Usage:       "Comma-separated list of interpreter tracers to include.",
					Destination: &args.tracers,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.BoolFlag{
					Name:        "verbose",
					Aliases:     []string{"v"},
					Value:       false,
					Usage:       "Enable verbose logging and debugging capabilities.",
					Destination: &args.verboseMode,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name:        "pprof-prefix",
					Usage:       "Dump pprof profile to `FILE`.",
					Destination: &args.pprofPrefix,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name: "node",
					Usage: "The name of the node that the profiler is running on. " +
						"If on Kubernetes, this must match the Kubernetes node name.",
					Destination: &args.node,
				}, longEnvVar),
			addDefaultEnvVar(
				&cli.BoolFlag{
					Name:        "upload-symbols",
					Value:       false,
					Usage:       "Enable local symbol upload.",
					Hidden:      true,
					Destination: &args.uploadSymbols,
				}, longEnvVar),
			&cli.BoolWithInverseFlag{
				BoolFlag: addDefaultEnvVar(
					&cli.BoolFlag{
						Name:  "upload-dynamic-symbols",
						Usage: "Enable dynamic symbols upload.",
						// Cannot set default value to true because it fails at runtime with:
						//   "Failure to parse arguments: cannot set both flags `--upload-dynamic-symbols`
						//    and `--no-upload-dynamic-symbols`"
						// Value:       true,
						DefaultText: "true",
						Hidden:      true,
					}, experimentalEnvVar),
			},
			addDefaultEnvVar(
				&cli.BoolFlag{
					Name:        "upload-symbols-dry-run",
					Value:       false,
					Usage:       "Local symbol upload dry-run.",
					Hidden:      true,
					Destination: &args.uploadSymbolsDryRun,
				}, experimentalEnvVar),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name:        "api-key",
					Usage:       "Datadog API key.",
					Hidden:      true,
					Destination: &args.apiKey,
					Validator: func(s string) error {
						if s == "" || isAPIKeyValid(s) {
							return nil
						}
						return errors.New("API key is not valid")
					},
				}, shortEnvVar),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name:        "app-key",
					Usage:       "Datadog APP key.",
					Hidden:      true,
					Destination: &args.appKey,
					Validator: func(s string) error {
						if s == "" || isAPPKeyValid(s) {
							return nil
						}
						return errors.New("APP key is not valid")
					},
				}, shortEnvVar),
			addDefaultEnvVar(
				&cli.StringFlag{
					Name:        "site",
					Value:       "datadoghq.com",
					Usage:       "Datadog site.",
					Hidden:      true,
					Destination: &args.site,
				}, shortEnvVar),
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			// Workaround for the fact that cli.BoolWithInverseFlag does not work with a false default value
			if cmd.IsSet("upload-dynamic-symbols") {
				args.uploadDynamicSymbols = cmd.Bool("upload-dynamic-symbols")
			} else {
				if cmd.Set("upload-dynamic-symbols", "true") != nil {
					return errors.New("cannot set flag `--upload-dynamic-symbols`")
				}
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
