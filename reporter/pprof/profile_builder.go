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

	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
	samples "github.com/DataDog/dd-otel-host-profiler/reporter/samples"
)

const unknownStr = "UNKNOWN"

type ProfileBuilder struct {
	profile            *pprofile.Profile
	funcMap            map[funcInfo]*pprofile.Function
	fileIDtoMapping    map[libpf.FileID]*pprofile.Mapping
	executables        *lru.SyncedLRU[libpf.FileID, samples.ExecInfo]
	processes          *lru.SyncedLRU[libpf.PID, samples.ProcessMetadata]
	timeline           bool
	totalSampleCount   int
	pidsWithNoMetadata libpf.Set[libpf.PID]
	samplingPeriod     int64
}

type ProfileStats struct {
	TotalSampleCount  int
	PidWithNoMetadata int
}

func NewProfileBuilder(start, end time.Time, samplesPerSecond int, numSamples int, timeline bool,
	executables *lru.SyncedLRU[libpf.FileID, samples.ExecInfo], processes *lru.SyncedLRU[libpf.PID, samples.ProcessMetadata]) *ProfileBuilder {
	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]*pprofile.Function)
	fileIDtoMapping := make(map[libpf.FileID]*pprofile.Mapping)

	samplingPeriod := 1000000000 / int64(samplesPerSecond)
	profile := &pprofile.Profile{
		SampleType: []*pprofile.ValueType{{Type: "cpu-samples", Unit: "count"},
			{Type: "cpu-time", Unit: "nanoseconds"}},
		Sample:            make([]*pprofile.Sample, 0, numSamples),
		PeriodType:        &pprofile.ValueType{Type: "cpu-time", Unit: "nanoseconds"},
		Period:            samplingPeriod,
		DefaultSampleType: "cpu-time",
	}
	profile.DurationNanos = end.Sub(start).Nanoseconds()
	profile.TimeNanos = start.UnixNano()

	return &ProfileBuilder{
		profile:            profile,
		funcMap:            funcMap,
		fileIDtoMapping:    fileIDtoMapping,
		executables:        executables,
		processes:          processes,
		pidsWithNoMetadata: libpf.Set[libpf.PID]{},
		timeline:           timeline,
		samplingPeriod:     samplingPeriod,
	}
}

func (b *ProfileBuilder) AddEvents(events samples.KeyToEventMapping) {
	for traceKey, traceInfo := range events {
		sample := &pprofile.Sample{}

		// Walk every frame of the trace.
		for _, uniqueFrame := range traceInfo.Frames {
			frame := uniqueFrame.Value()
			loc := b.createPProfLocation(uint64(frame.AddressOrLineno))

			switch frameKind := frame.Type; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.
				loc.Mapping = b.createPprofMappingForFileID(frame.FileID)
				loc.Line = append(loc.Line, pprofile.Line{Function: b.createPprofFunctionEntry("", loc.Mapping.File)})
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as Line message:
				line := pprofile.Line{
					Line:     int64(frame.SourceLine),
					Function: b.createPprofFunctionEntry(frame.FunctionName.String(), frame.SourceFile.String()),
				}

				loc.Line = append(loc.Line, line)
				// To be compliant with the protocol generate a dummy mapping entry.
				loc.Mapping = b.getDummyMapping(frame.FileID)
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
			if processMeta.ProcessName != "" {
				baseExec = processMeta.ProcessName
			} else {
				baseExec = execPath
			}

		default:
			b.pidsWithNoMetadata[traceKey.Pid] = libpf.Void{}
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
		if b.timeline {
			count = int64(len(traceInfo.Timestamps))
		}

		labels := make(map[string][]string)
		addTraceLabels(labels, traceKey, processMeta.ContainerMetadata, baseExec)
		sample.Label = labels
		sample.Value = append(sample.Value, count, count*b.samplingPeriod)

		if !b.timeline {
			b.profile.Sample = append(b.profile.Sample, sample)
		} else {
			for _, ts := range traceInfo.Timestamps {
				sampleWithTimestamp := &pprofile.Sample{}
				*sampleWithTimestamp = *sample
				sampleWithTimestamp.NumLabel = make(map[string][]int64)
				sampleWithTimestamp.NumLabel["timestamp_ns"] = append(sampleWithTimestamp.NumLabel["timestamp_ns"], int64(ts))
				b.profile.Sample = append(b.profile.Sample, sampleWithTimestamp)
			}
		}
		b.totalSampleCount += len(traceInfo.Timestamps)
	}
}

func (b *ProfileBuilder) Build() (*pprofile.Profile, ProfileStats) {
	profile := b.profile.Compact()
	stats := ProfileStats{
		TotalSampleCount:  b.totalSampleCount,
		PidWithNoMetadata: len(b.pidsWithNoMetadata),
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

// getDummyMappingIndex inserts or looks up a dummy entry for interpreted FileIDs.
func (b *ProfileBuilder) getDummyMapping(fileID libpf.FileID) *pprofile.Mapping {
	if tmpMapping, exists := b.fileIDtoMapping[fileID]; exists {
		return tmpMapping
	}

	mapping := b.createPprofMapping("DUMMY", fileID.StringNoQuotes())
	b.fileIDtoMapping[fileID] = mapping

	return mapping
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

func (b *ProfileBuilder) createPprofMappingForFileID(fileID libpf.FileID) *pprofile.Mapping {
	if mapping, exists := b.fileIDtoMapping[fileID]; exists {
		return mapping
	}

	executionInfo, exists := b.executables.GetAndRefresh(fileID, samples.ExecutableCacheLifetime)

	fileName := unknownStr
	buildID := fileID.StringNoQuotes()
	if exists {
		fileName = executionInfo.FileName
		buildID = samples.GetBuildID(executionInfo.GnuBuildID, executionInfo.GoBuildID, buildID)
	}

	mapping := b.createPprofMapping(fileName, buildID)
	b.fileIDtoMapping[fileID] = mapping
	return mapping
}

func (b *ProfileBuilder) createPprofMapping(fileName, buildID string) *pprofile.Mapping {
	idx := uint64(len(b.profile.Mapping)) + 1
	mapping := &pprofile.Mapping{
		ID:      idx,
		File:    fileName,
		Offset:  0,
		BuildID: buildID,
	}
	b.profile.Mapping = append(b.profile.Mapping, mapping)
	return mapping
}

func addTraceLabels(labels map[string][]string, i samples.TraceAndMetaKey, containerMetadata containermetadata.ContainerMetadata,
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
