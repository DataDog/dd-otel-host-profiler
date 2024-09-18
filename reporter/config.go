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
	// Name defines the name of the agent.
	Name string
	// Version defines the version of the agent.
	Version string
	// CollAgentAddr defines the destination of the backend connection.
	CollAgentAddr string
	// CacheSize defines the size of the reporter caches.
	CacheSize uint32
	// samplesPerSecond defines the number of samples per second.
	SamplesPerSecond int
	// HostID is the host ID to be sent to the collection agent.
	HostID uint64
	// KernelVersion is the kernel version of the host.
	KernelVersion string
	// HostName is the name of the host.
	HostName string
	// IPAddress is the IP address of the host.
	IPAddress string
	// ReportInterval defines the interval at which the agent reports data to the collection agent.
	ReportInterval time.Duration
	// SaveCPUProfile defines whether the agent should dump a pprof CPU profile on disk.
	SaveCPUProfile bool
	// Tags is a list of tags to be sent to the collection agent.
	Tags Tags
	// SymbolUpload defines whether the agent should upload debug symbols to the backend.
	UploadSymbols bool
}
