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
	// EnableSplitByService defines whether the agent should split profiles by service.
	EnableSplitByService bool
	// SplitServiceSuffix defines the suffix to add to service name in profiles when split-by-service is enabled.
	SplitServiceSuffix string
	// UseRuntimeIDInServiceEntityKey defines whether to use runtimeID in service entity key.
	UseRuntimeIDInServiceEntityKey bool
	// HostServiceName defines the service name to use in profiles (in non-split-by-service mode).
	HostServiceName string
	// KernelSupportsNamedAnonymousMappings defines whether the kernel supports named anonymous mappings (PR_SET_VMA_ANON_NAME).
	KernelSupportsNamedAnonymousMappings bool
	// CollectContext defines whether the agent should collect tracing context from processes.
	CollectContext bool
	// SymbolUploaderConfig defines the configuration for the symbol uploader.
	SymbolUploaderConfig SymbolUploaderConfig
}

type SymbolUploaderOptions struct {
	// Enabled defines whether the agent should upload debug symbols to the backend.
	Enabled bool `mapstructure:"enabled"`
	// UploadDynamicSymbols defines whether the agent should upload dynamic symbols to the backend.
	UploadDynamicSymbols bool `mapstructure:"upload_dynamic_symbols"`
	// UploadGoPCLnTab defines whether the agent should upload GoPCLnTab section for Go binaries to the backend.
	UploadGoPCLnTab bool `mapstructure:"upload_go_pcln_tab"`
	// UseHTTP2 defines whether the agent should use HTTP/2 when uploading symbols.
	UseHTTP2 bool `mapstructure:"use_http2"`
	// SymbolQueryInterval defines the interval at which the agent should query the backend for symbols. A value of 0 disables batching.
	SymbolQueryInterval time.Duration `mapstructure:"symbol_query_interval"`
	// DryRun defines whether the agent should upload debug symbols to the backend in dry-run mode.
	DryRun bool `mapstructure:"dry_run"`
	// Sites to upload symbols to.
	SymbolEndpoints []SymbolEndpoint `mapstructure:"symbol_endpoints"`

	// IMPORTANT NOTE: If you add a new option, you must update the code in datadog-agent repository as well to use the same default value.
	// See https://github.com/DataDog/datadog-agent/pull/41709/files#diff-c0739e376456cf23d49566fb4c959182e3fa29a8670a55658306a4a9e189fc13R67-R72
}

type SymbolUploaderConfig struct {
	// Options defines the options for the symbol uploader.
	SymbolUploaderOptions `mapstructure:",squash"`

	// DisableDebugSectionCompression defines whether the uploader should disable debug section compression whatever objcopy supports.
	// This is only used for testing purposes.
	DisableDebugSectionCompression bool `mapstructure:"disable_debug_section_compression"`
	// Version is the version of the profiler.
	Version string
}
