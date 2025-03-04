// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package reporter

import (
	"time"
)

type Tag struct {
	Key   string
	Value string
}

type Tags []Tag

func MakeTag(key, value string) Tag {
	return Tag{
		Key:   key,
		Value: value,
	}
}

type Config struct {
	// Version defines the version of the agent.
	Version string
	// IntakeURL defines the URL of profiling intake.
	IntakeURL string
	// ExecutablesCacheElements defines item capacity of the executables cache.
	ExecutablesCacheElements uint32
	// FramesCacheElements defines the item capacity of the frames cache.
	FramesCacheElements uint32
	// ProcessesCacheElements defines the item capacity of the processes cache.
	ProcessesCacheElements uint32
	// samplesPerSecond defines the number of samples per second.
	SamplesPerSecond int
	// ReportInterval defines the interval at which the agent reports data to the collection agent.
	ReportInterval time.Duration
	// PprofPrefix defines a file where the agent should dump pprof CPU profile.
	PprofPrefix string
	// Tags is a list of tags to be sent to the collection agent.
	Tags Tags
	// Whether to include timestamps on samples for the timeline feature
	Timeline bool
	// API key for agentless mode
	APIKey string
	// SymbolUploaderConfig defines the configuration for the symbol uploader.
	SymbolUploaderConfig SymbolUploaderConfig
}

type SymbolUploaderConfig struct {
	// Enabled defines whether the agent should upload debug symbols to the backend.
	Enabled bool
	// UploadDynamicSymbols defines whether the agent should upload dynamic symbols to the backend.
	UploadDynamicSymbols bool
	// UploadGoPCLnTab defines whether the agent should upload GoPCLnTab section for Go binaries to the backend.
	UploadGoPCLnTab bool
	// DryRun defines whether the agent should upload debug symbols to the backend in dry-run mode.
	DryRun bool
	// Sites to upload symbols to.
	SymbolEndpoints []SymbolEndpoint
	// Version is the version of the profiler.
	Version string
}
