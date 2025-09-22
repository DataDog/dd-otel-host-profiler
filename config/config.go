// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package config

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/DataDog/dd-otel-host-profiler/reporter"
)

type additionalSymbolEndpoints []reporter.SymbolEndpoint

// String allows us to implement the cli.Value interface
// It is used to convert the value to a string when printing the help message
func (s *additionalSymbolEndpoints) String() string {
	if s == nil {
		return ""
	}
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// Set allows us to implement the cli.Value interface
// It is used to set the value from the command line
func (s *additionalSymbolEndpoints) Set(value string) error {
	if value == "" {
		return nil
	}
	err := json.Unmarshal([]byte(value), s)
	if err != nil {
		return errors.New("invalid JSON")
	}
	return nil
}

// Get allows us to implement the cli.Value interface
// It is not used currently in our setup
func (s *additionalSymbolEndpoints) Get() interface{} {
	return s
}

type Config struct {
	BPFVerifierLogLevel           uint64
	AgentURL                      string
	MapScaleFactor                uint64
	MonitorInterval               time.Duration
	ClockSyncInterval             time.Duration
	NoKernelVersionCheck          bool
	Node                          string
	ProbabilisticInterval         time.Duration
	ProbabilisticThreshold        uint64
	ReporterInterval              time.Duration
	SamplesPerSecond              uint64
	PprofPrefix                   string
	SendErrorFrames               bool
	HostServiceName               string
	Environment                   string
	UploadSymbolQueryInterval     time.Duration
	UploadSymbols                 bool
	UploadSymbolsHTTP2            bool
	UploadDynamicSymbols          bool
	UploadGoPCLnTab               bool
	UploadSymbolsDryRun           bool
	Tags                          string
	Timeline                      bool
	Tracers                       string
	VerboseeBPF                   bool
	APIKey                        string
	AppKey                        string
	Site                          string
	AdditionalSymbolEndpoints     additionalSymbolEndpoints
	Agentless                     bool
	EnableGoRuntimeProfiler       bool
	GoRuntimeProfilerPeriod       time.Duration
	GoRuntimeMetricsStatsdAddress string
	EnableSplitByService          bool
	SplitServiceSuffix            string
	CollectContext                bool
}
