// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package pprof

import (
	"fmt"
	"path"
	"time"

	lru "github.com/elastic/go-freelru"
	pprofile "github.com/google/pprof/profile"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	samples "github.com/DataDog/dd-otel-host-profiler/reporter/samples"
)

const unknownStr = "UNKNOWN"

type Config struct {
	Start                       time.Time
	End                         time.Time
	SamplesPerSecond            int
	NumSamples                  int
	Timeline                    bool
	ProcessLevelContextAsLabels bool
	Processes                   *lru.SyncedLRU[libpf.PID, samples.ProcessMetadata]
}

type ProfileBuilder struct {
	profile                     *pprofile.Profile
	funcMap                     map[funcInfo]*pprofile.Function
	mappings                    map[uniqueMapping]*pprofile.Mapping
	processes                   *lru.SyncedLRU[libpf.PID, samples.ProcessMetadata]
	timeline                    bool
	processLevelContextAsLabels bool
	totalSampleCount            int
	pidsWithNoMetadata          libpf.Set[libpf.PID]
	samplingPeriod              int64
}

type ProfileStats struct {
	TotalSampleCount int
}

// uniqueMapping defines an unique mapping in a process.
type uniqueMapping struct {
	// mapping start in the ELF virtual address space
	Start libpf.Address
	// mapping file
	File libpf.FrameMappingFile
}

func NewProfileBuilder(cfg *Config) *ProfileBuilder {
	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]*pprofile.Function)
	mappings := make(map[uniqueMapping]*pprofile.Mapping)

	samplingPeriod := 1000000000 / int64(cfg.SamplesPerSecond)
	profile := &pprofile.Profile{
		SampleType: []*pprofile.ValueType{{Type: "cpu-samples", Unit: "count"},
			{Type: "cpu-time", Unit: "nanoseconds"}},
		Sample:            make([]*pprofile.Sample, 0, cfg.NumSamples),
		PeriodType:        &pprofile.ValueType{Type: "cpu-time", Unit: "nanoseconds"},
		Period:            samplingPeriod,
		DefaultSampleType: "cpu-time",
	}
	profile.DurationNanos = cfg.End.Sub(cfg.Start).Nanoseconds()
	profile.TimeNanos = cfg.Start.UnixNano()

	return &ProfileBuilder{
		profile:                     profile,
		funcMap:                     funcMap,
		mappings:                    mappings,
		processes:                   cfg.Processes,
		pidsWithNoMetadata:          libpf.Set[libpf.PID]{},
		timeline:                    cfg.Timeline,
		processLevelContextAsLabels: cfg.ProcessLevelContextAsLabels,
		samplingPeriod:              samplingPeriod,
	}
}

func (b *ProfileBuilder) AddEvents(events samples.KeyToEventMapping) {
	for traceKey, traceInfo := range events {
		sample := &pprofile.Sample{}

		// Walk every frame of the trace.
		for _, uniqueFrame := range traceInfo.Frames {
			frame := uniqueFrame.Value()
			loc := b.createPProfLocation(uint64(frame.AddressOrLineno))
			loc.Mapping = b.createPprofMappingForFrame(&frame)

			if frame.FunctionName != libpf.NullString || frame.SourceFile != libpf.NullString {
				line := pprofile.Line{
					Line:     int64(frame.SourceLine),
					Function: b.createPprofFunctionEntry(frame.FunctionName.String(), frame.SourceFile.String()),
				}
				loc.Line = append(loc.Line, line)
			}
			sample.Location = append(sample.Location, loc)
		}

		processMeta, _ := b.processes.Get(traceKey.Pid)
		execPath := processMeta.ExecutablePath

		var baseExec string

		switch {
		case execPath != "":
			baseExec = path.Base(execPath)

		case samples.IsKernel(traceInfo.Frames):
			execPath = "kernel"
			baseExec = execPath

		default:
			execPath = traceKey.Comm
			baseExec = execPath
		}

		if execPath != "" {
			loc := b.createPProfLocation(0)
			m := b.createPprofFunctionEntry(baseExec, execPath)
			loc.Line = append(loc.Line, pprofile.Line{Function: m})
			sample.Location = append(sample.Location, loc)
		}

		var count int64 = 1
		splitSample := hasCustomLabels(traceInfo) || b.timeline
		if !splitSample {
			count = int64(len(traceInfo.Timestamps))
		}

		labels := make(map[string][]string)
		addTraceLabels(labels, traceKey, &processMeta, baseExec)
		if processMeta.TracingContext != nil && b.processLevelContextAsLabels {
			addProcessLevelContextAsLabels(labels, processMeta.TracingContext)
		}
		sample.Label = labels
		sample.Value = append(sample.Value, count, count*b.samplingPeriod)

		if !splitSample {
			b.profile.Sample = append(b.profile.Sample, sample)
		} else {
			for ix, ts := range traceInfo.Timestamps {
				sampleCopy := &pprofile.Sample{}
				*sampleCopy = *sample

				if b.timeline {
					sampleCopy.NumLabel = make(map[string][]int64)
					sampleCopy.NumLabel["timestamp_ns"] = append(sampleCopy.NumLabel["timestamp_ns"], int64(ts))
				}
				if len(traceInfo.CustomLabels) > 0 && len(traceInfo.CustomLabels[ix]) > 0 {
					sampleCopy.Label = addCustomLabels(sampleCopy.Label, traceInfo.CustomLabels[ix])
				}
				b.profile.Sample = append(b.profile.Sample, sampleCopy)
			}
		}
		b.totalSampleCount += len(traceInfo.Timestamps)
	}
}

func (b *ProfileBuilder) Build() (*pprofile.Profile, ProfileStats) {
	profile := b.profile.Compact()
	stats := ProfileStats{
		TotalSampleCount: b.totalSampleCount,
	}
	return profile, stats
}

// funcInfo is a helper to construct profile.Function messages.
type funcInfo struct {
	name     string
	fileName string
}

// createFunctionEntry adds a new function and returns its reference index.
func (b *ProfileBuilder) createPprofFunctionEntry(name, fileName string) *pprofile.Function {
	key := funcInfo{
		name:     name,
		fileName: fileName,
	}
	if function, exists := b.funcMap[key]; exists {
		return function
	}

	idx := uint64(len(b.profile.Function)) + 1
	function := &pprofile.Function{
		ID:       idx,
		Name:     name,
		Filename: fileName,
	}
	b.profile.Function = append(b.profile.Function, function)
	b.funcMap[key] = function

	return function
}

func (b *ProfileBuilder) createPProfLocation(address uint64) *pprofile.Location {
	idx := uint64(len(b.profile.Location)) + 1
	location := &pprofile.Location{
		ID:      idx,
		Address: address,
	}
	b.profile.Location = append(b.profile.Location, location)
	return location
}

func (b *ProfileBuilder) createPprofMappingForFrame(frame *libpf.Frame) *pprofile.Mapping {
	if !frame.MappingFile.Valid() {
		return nil
	}

	if mapping, exists := b.mappings[uniqueMapping{Start: frame.MappingStart, File: frame.MappingFile}]; exists {
		return mapping
	}

	mf := frame.MappingFile.Value()
	fileName := unknownStr
	if mf.FileName != libpf.NullString {
		fileName = mf.FileName.String()
	}
	buildID := samples.GetBuildID(mf.GnuBuildID, mf.GoBuildID, mf.FileID)

	mapping := b.createPprofMapping(fileName, buildID, frame.MappingStart, frame.MappingFileOffset)
	b.mappings[uniqueMapping{Start: frame.MappingStart, File: frame.MappingFile}] = mapping
	return mapping
}

func (b *ProfileBuilder) createPprofMapping(fileName, buildID string, start libpf.Address, offset uint64) *pprofile.Mapping {
	idx := uint64(len(b.profile.Mapping)) + 1
	mapping := &pprofile.Mapping{
		ID:      idx,
		File:    fileName,
		Start:   uint64(start),
		Offset:  offset,
		BuildID: buildID,
	}
	b.profile.Mapping = append(b.profile.Mapping, mapping)
	return mapping
}

func addTraceLabels(labels map[string][]string, i samples.TraceAndMetaKey, processMeta *samples.ProcessMetadata,
	processName string) {
	// The naming has an impact on the backend side,
	// this is why we use "thread id", "thread name" and "process name"
	if i.Tid != 0 {
		labels["thread id"] = append(labels["thread id"], fmt.Sprintf("%d", i.Tid))
	}

	if i.Pid != 0 {
		labels["process_id"] = append(labels["process_id"], fmt.Sprintf("%d", i.Pid))
	}

	if i.Comm != "" {
		labels["thread name"] = append(labels["thread name"], i.Comm)
	}

	if processName != "" {
		labels["process name"] = append(labels["process name"], processName)
	}

	containerMetadata := processMeta.ContainerMetadata
	if containerMetadata.PodName != "" {
		labels["pod_name"] = append(labels["pod_name"], containerMetadata.PodName)
	}

	// In split by service, ContainerID always empty.
	if containerMetadata.ContainerID != "" {
		labels["container_id"] = append(labels["container_id"], containerMetadata.ContainerID)
	}

	if containerMetadata.ContainerName != "" {
		labels["container_name"] = append(labels["container_name"], containerMetadata.ContainerName)
	}
}

func addProcessLevelContextAsLabels(labels map[string][]string, tracingCtx *samples.ProcessContext) {
	if tracingCtx.DeploymentEnvironmentName != "" {
		labels["env"] = append(labels["env"], tracingCtx.DeploymentEnvironmentName)
	}

	if tracingCtx.ServiceInstanceID != "" {
		labels["runtime_id"] = append(labels["runtime_id"], tracingCtx.ServiceInstanceID)
	}

	if tracingCtx.ServiceName != "" {
		labels["service_name"] = append(labels["service_name"], tracingCtx.ServiceName)
	}

	if tracingCtx.ServiceVersion != "" {
		labels["service_version"] = append(labels["service_version"], tracingCtx.ServiceVersion)
	}

	if tracingCtx.HostName != "" {
		labels["host_name"] = append(labels["host_name"], tracingCtx.HostName)
	}

	if tracingCtx.TelemetrySdkLanguage != "" {
		labels["telemetry_sdk_language"] = append(labels["telemetry_sdk_language"], tracingCtx.TelemetrySdkLanguage)
	}

	if tracingCtx.TelemetrySdkName != "" {
		labels["telemetry_sdk_name"] = append(labels["telemetry_sdk_name"], tracingCtx.TelemetrySdkName)
	}

	if tracingCtx.TelemetrySdkVersion != "" {
		labels["telemetry_sdk_version"] = append(labels["telemetry_sdk_version"], tracingCtx.TelemetrySdkVersion)
	}
}

func hasCustomLabels(traceInfo *samples.TraceEvents) bool {
	if len(traceInfo.CustomLabels) == 0 {
		return false
	}
	for _, customLabels := range traceInfo.CustomLabels {
		if len(customLabels) > 0 {
			return true
		}
	}
	return false
}

func addCustomLabels(labels map[string][]string, customLabels map[string]string) map[string][]string {
	labelsCopy := make(map[string][]string)
	for key, value := range labels {
		labelsCopy[key] = append(labelsCopy[key], value...)
	}
	for key, value := range customLabels {
		labelsCopy[key] = append(labelsCopy[key], value)
	}
	return labelsCopy
}
