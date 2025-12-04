// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package samples

import (
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"

	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
)

const ExecutableCacheLifetime = 1 * time.Hour // executable cache items will be removed if unused after this interval

// ExecInfo enriches an executable with additional metadata.
type ExecInfo struct {
	FileName   string
	GnuBuildID string
	GoBuildID  string
}

// TraceAndMetaKey is the deduplication key for samples. This **must always**
// contain all trace fields that aren't already part of the trace hash to ensure
// that we don't accidentally merge traces with different fields.
type TraceAndMetaKey struct {
	Hash libpf.TraceHash
	// Comm is provided by the eBPF programs
	Comm string
	Pid  libpf.PID
	Tid  libpf.PID
	CPU  int64
}

// TraceEvents from ebpf-profiler/reporter/samples cannot be used here because
// it stores the labels as a single map[string]string for all traceevents sharing
// the same TraceAndMetaKey.
// Labels can be different for each traceevent though (eg. span ID), so we need
// to store them for each traceevent as it's done for timestamps / offtimes.
// The alternative would be to make labels part of the TraceAndMetaKey.
type TraceEvents struct {
	samples.TraceEvents

	CustomLabels []map[libpf.String]libpf.String
}

type ProcessContext struct {
	ServiceName               string `msgpack:"service.name"`
	ServiceVersion            string `msgpack:"service.version"`
	ServiceInstanceID         string `msgpack:"service.instance.id"`
	DeploymentEnvironmentName string `msgpack:"deployment.environment.name"`
	HostName                  string `msgpack:"host.name"`
	TelemetrySdkLanguage      string `msgpack:"telemetry.sdk.language"`
	TelemetrySdkName          string `msgpack:"telemetry.sdk.name"`
	TelemetrySdkVersion       string `msgpack:"telemetry.sdk.version"`
}

type ProcessMetadata struct {
	UpdatedAt         time.Time
	ExecutablePath    string
	ProcessName       string
	ContainerMetadata containermetadata.ContainerMetadata
	Service           string
	InferredService   bool
	TracingContext    *ProcessContext
}

type ServiceEntity struct {
	Service         string
	EntityID        string
	RuntimeID       string
	InferredService bool
}

type TraceEventsTree map[ServiceEntity]map[libpf.Origin]KeyToEventMapping

type KeyToEventMapping map[TraceAndMetaKey]*TraceEvents

func fileHash(fileID libpf.FileID) string {
	if fileID == (libpf.FileID{}) {
		return ""
	}
	return fileID.StringNoQuotes()
}

func GetBuildID(gnuBuildID, goBuildID string, fileID libpf.FileID) string {
	// When building Go binaries, Bazel will set the Go build ID to "redacted" to
	// achieve deterministic builds. Since Go 1.24, the Gnu Build ID is inherited
	// from the Go build ID - if the Go build ID is "redacted", the Gnu Build ID will
	// be a hash of "redacted". In this case, we should use the file hash instead of build IDs.
	if goBuildID == "redacted" {
		return fileHash(fileID)
	}
	if gnuBuildID != "" {
		return gnuBuildID
	}
	if goBuildID != "" {
		return goBuildID
	}

	return fileHash(fileID)
}

func IsKernel(frames libpf.Frames) bool {
	if len(frames) == 0 {
		return false
	}

	return frames[len(frames)-1].Value().Type == libpf.KernelFrame
}
