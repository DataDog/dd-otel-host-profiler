/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/peterbourgon/ff/v3"
	log "github.com/sirupsen/logrus"

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

// Help strings for command line arguments
var (
	noKernelVersionCheckHelp = "Disable checking kernel version for eBPF support. " +
		"Use at your own risk, to run the agent on older kernels with backported eBPF features."
	collAgentAddrHelp  = "The Datadog agent URL in the format of http://host:port."
	copyrightHelp      = "Show copyright and short license text."
	verboseModeHelp    = "Enable verbose logging and debugging capabilities."
	tracersHelp        = "Comma-separated list of interpreter tracers to include."
	mapScaleFactorHelp = fmt.Sprintf("Scaling factor for eBPF map sizes. "+
		"Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. "+
		"Default is %d corresponding to 4GB of executable address space, max is %d.",
		defaultArgMapScaleFactor, maxArgMapScaleFactor)
	bpfVerifierLogLevelHelp = "Log level of the eBPF verifier output (0,1,2). Default is 0."
	bpfVerifierLogSizeHelp  = "Size in bytes that will be allocated for the eBPF " +
		"verifier output. Only takes effect if bpf-log-level > 0."
	versionHelp                = "Show version."
	probabilisticThresholdHelp = fmt.Sprintf("If set to a value between 1 and %d will enable "+
		"probabilistic profiling: "+
		"every probabilistic-interval a random number between 0 and %d is "+
		"chosen. If the given probabilistic-threshold is greater than this "+
		"random number, the agent will collect profiles from this system for "+
		"the duration of the interval.",
		tracer.ProbabilisticThresholdMax-1, tracer.ProbabilisticThresholdMax-1)
	probabilisticIntervalHelp = "Time interval for which probabilistic profiling will be " +
		"enabled or disabled."
	pprofHelp             = "Listening address (e.g. localhost:6060) to serve pprof information."
	samplesPerSecondHelp  = "Set the frequency (in Hz) of stack trace sampling."
	reporterIntervalHelp  = "Set the reporter's interval in seconds."
	monitorIntervalHelp   = "Set the monitor interval in seconds."
	clockSyncIntervalHelp = "Set the sync interval with the realtime clock. " +
		"If zero, monotonic-realtime clock sync will be performed once, " +
		"on agent startup, but not periodically."
	sendErrorFramesHelp = "Send error frames (devfiler only, breaks Kibana)"
	saveCPUProfileHelp  = "Save CPU pprof profile to `cpu.pprof`."
	tagsHelp            = "User-specified tags separated by ';'."
	serviceHelp         = "Service name."
	nodeHelp            = "The name of the node that the profiler is running on. " +
		"If on Kubernetes, this must match the Kubernetes node name."
)

type arguments struct {
	bpfVerifierLogLevel    uint
	bpfVerifierLogSize     int
	collAgentAddr          string
	copyright              bool
	mapScaleFactor         uint
	monitorInterval        time.Duration
	clockSyncInterval      time.Duration
	noKernelVersionCheck   bool
	node                   string
	pprofAddr              string
	probabilisticInterval  time.Duration
	probabilisticThreshold uint
	reporterInterval       time.Duration
	samplesPerSecond       int
	saveCPUProfile         bool
	sendErrorFrames        bool
	serviceName            string
	symbolUpload           bool
	tags                   string
	timeline               bool
	tracers                string
	verboseMode            bool
	version                bool

	fs *flag.FlagSet
}

// Package-scope variable, so that conditionally compiled other components can refer
// to the same flagset.

func parseArgs() (*arguments, error) {
	var args arguments
	var err error

	fs := flag.NewFlagSet("dd-otel-host-profiler", flag.ExitOnError)

	// Please keep the parameters ordered alphabetically in the source-code.
	fs.UintVar(&args.bpfVerifierLogLevel, "bpf-log-level", 0, bpfVerifierLogLevelHelp)
	fs.IntVar(&args.bpfVerifierLogSize, "bpf-log-size", cebpf.DefaultVerifierLogSize,
		bpfVerifierLogSizeHelp)

	fs.StringVar(&args.collAgentAddr, "collection-agent", defaultArgCollAgentAddr,
		collAgentAddrHelp)

	fs.BoolVar(&args.copyright, "copyright", false, copyrightHelp)
	fs.UintVar(&args.mapScaleFactor, "map-scale-factor",
		defaultArgMapScaleFactor, mapScaleFactorHelp)

	fs.DurationVar(&args.monitorInterval, "monitor-interval", defaultArgMonitorInterval,
		monitorIntervalHelp)

	fs.DurationVar(&args.clockSyncInterval, "clock-sync-interval", defaultClockSyncInterval,
		clockSyncIntervalHelp)

	fs.BoolVar(&args.noKernelVersionCheck, "no-kernel-version-check", false,
		noKernelVersionCheckHelp)

	fs.StringVar(&args.pprofAddr, "pprof", "", pprofHelp)

	fs.DurationVar(&args.probabilisticInterval, "probabilistic-interval",
		defaultProbabilisticInterval, probabilisticIntervalHelp)
	fs.UintVar(&args.probabilisticThreshold, "probabilistic-threshold",
		defaultProbabilisticThreshold, probabilisticThresholdHelp)

	fs.DurationVar(&args.reporterInterval, "reporter-interval", defaultArgReporterInterval,
		reporterIntervalHelp)

	fs.IntVar(&args.samplesPerSecond, "samples-per-second", defaultArgSamplesPerSecond,
		samplesPerSecondHelp)
	fs.BoolVar(&args.timeline, "timeline", false, "Enable timeline feature.")

	fs.BoolVar(&args.sendErrorFrames, "send-error-frames", defaultArgSendErrorFrames,
		sendErrorFramesHelp)

	fs.StringVar(&args.tracers, "t", "all", "Shorthand for -tracers.")
	fs.StringVar(&args.tracers, "tracers", "all", tracersHelp)

	fs.BoolVar(&args.verboseMode, "v", false, "Shorthand for -verbose.")
	fs.BoolVar(&args.verboseMode, "verbose", false, verboseModeHelp)
	fs.BoolVar(&args.version, "version", false, versionHelp)

	fs.StringVar(&args.tags, "tags", "", tagsHelp)
	fs.BoolVar(&args.saveCPUProfile, "save-cpuprofile", false,
		saveCPUProfileHelp)
	fs.StringVar(&args.serviceName, "service", "dd-otel-host-profiler", serviceHelp)

	fs.StringVar(&args.node, "node", "", nodeHelp)

	fs.Usage = func() {
		fs.PrintDefaults()
	}

	args.fs = fs

	symbolUpload := os.Getenv("DD_EXPERIMENTAL_LOCAL_SYMBOL_UPLOAD")
	if symbolUpload != "" {
		args.symbolUpload, err = strconv.ParseBool(symbolUpload)
		if err != nil {
			args.symbolUpload = false
			log.Warnf("Failed to parse DD_EXPERIMENTAL_LOCAL_SYMBOL_UPLOAD=%v: %v", symbolUpload, err)
		}
	}

	return &args, ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("DD_OTEL_HOST_PROFILER"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ff.PlainParser),
		// This will ignore configuration file (only) options that the current HA
		// does not recognize.
		ff.WithIgnoreUndefined(true),
		ff.WithAllowMissingConfigFile(true),
	)
}

func (args *arguments) dump() {
	log.Debug("Config:")
	args.fs.VisitAll(func(f *flag.Flag) {
		log.Debug(fmt.Sprintf("%s: %v", f.Name, f.Value))
	})
}
