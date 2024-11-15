// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"path"
	"runtime"
	"strconv"
	"time"

	"github.com/DataDog/zstd"
	lru "github.com/elastic/go-freelru"
	pprofile "github.com/google/pprof/profile"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"

	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
)

// Assert that we implement the full Reporter interface.
var _ reporter.Reporter = (*DatadogReporter)(nil)

const profilerName = "dd-otel-host-profiler"

// execInfo enriches an executable with additional metadata.
type execInfo struct {
	fileName string
	buildID  string
}

// sourceInfo allows mapping a frame to its source origin.
type sourceInfo struct {
	lineNumber     libpf.SourceLineno
	functionOffset uint32
	functionName   string
	filePath       string
}

// funcInfo is a helper to construct profile.Function messages.
type funcInfo struct {
	name     string
	fileName string
}

// traceAndMetaKey is the deduplication key for samples. This **must always**
// contain all trace fields that aren't already part of the trace hash to ensure
// that we don't accidentally merge traces with different fields.
type traceAndMetaKey struct {
	hash libpf.TraceHash
	// comm and apmServiceName are provided by the eBPF programs
	comm           string
	apmServiceName string
	pid            libpf.PID
	tid            libpf.PID
}

// traceEvents holds known information about a trace.
type traceEvents struct {
	files              []libpf.FileID
	linenos            []libpf.AddressOrLineno
	frameTypes         []libpf.FrameType
	mappingStarts      []libpf.Address
	mappingEnds        []libpf.Address
	mappingFileOffsets []uint64
	timestamps         []uint64 // in nanoseconds

}

type processMetadata struct {
	execPath          string
	containerMetadata containermetadata.ContainerMetadata
}

// DatadogReporter receives and transforms information to be OTLP/profiles compliant.
type DatadogReporter struct {
	// profiler version
	version string

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long term storage information that might
	// be duplicated in other places but not accessible for DatadogReporter.

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[traceAndMetaKey]*traceEvents]

	// processes stores the metadata associated to a PID.
	processes *lru.SyncedLRU[libpf.PID, processMetadata]

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int

	// intakeURL is the intake URL
	intakeURL string

	// pprofPrefix defines a file where the agent should dump pprof CPU profile.
	pprofPrefix string

	// tags is a list of tags alongside the profile.
	tags Tags

	// timeline is a flag to include timestamps on samples for the timeline feature.
	timeline bool

	// API key for agentless mode
	apiKey string

	symbolUploader *DatadogSymbolUploader

	containerMetadataProvider containermetadata.Provider

	// profileSeq is the sequence number of the profile (ie. number of profiles uploaded until now).
	profileSeq uint64
}

// SupportsReportTraceEvent returns true if the reporter supports reporting trace events
// via ReportTraceEvent().
func (r *DatadogReporter) SupportsReportTraceEvent() bool {
	return true
}

// ReportTraceEvent enqueues reported trace events for the Datadog reporter.
func (r *DatadogReporter) ReportTraceEvent(trace *libpf.Trace, meta *reporter.TraceEventMeta) {
	traceEventsMap := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEventsMap)

	if _, ok := r.processes.Get(meta.PID); !ok {
		r.addProcessMetadata(meta.PID)
	}

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           meta.Comm,
		apmServiceName: meta.APMServiceName,
		pid:            meta.PID,
		tid:            meta.TID,
	}

	if tr, exists := (*traceEventsMap)[key]; exists {
		tr.timestamps = append(tr.timestamps, uint64(meta.Timestamp))
		(*traceEventsMap)[key] = tr
		return
	}

	(*traceEventsMap)[key] = &traceEvents{
		files:              trace.Files,
		linenos:            trace.Linenos,
		frameTypes:         trace.FrameTypes,
		mappingStarts:      trace.MappingStart,
		mappingEnds:        trace.MappingEnd,
		mappingFileOffsets: trace.MappingFileOffsets,
		timestamps:         []uint64{uint64(meta.Timestamp)},
	}
}

// ReportFramesForTrace is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *reporter.TraceEventMeta) {
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *DatadogReporter) ExecutableMetadata(fileID libpf.FileID, filePath, buildID string,
	interp libpf.InterpreterType, opener process.FileOpener) {
	r.executables.Add(fileID, execInfo{
		fileName: path.Base(filePath),
		buildID:  buildID,
	})

	if r.symbolUploader != nil && interp == libpf.Native {
		r.symbolUploader.UploadSymbols(fileID, filePath, buildID, opener)
	}
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *DatadogReporter) FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno,
	lineNumber libpf.SourceLineno, functionOffset uint32, functionName, filePath string) {
	if frameMapLock, exists := r.frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		if filePath == "" {
			// The new filePath may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				filePath = s.filePath
			}
		}

		(*frameMap)[addressOrLine] = sourceInfo{
			lineNumber:     lineNumber,
			functionOffset: functionOffset,
			functionName:   functionName,
			filePath:       filePath,
		}

		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     lineNumber,
		functionOffset: functionOffset,
		functionName:   functionName,
		filePath:       filePath,
	}
	mu := xsync.NewRWMutex(v)
	r.frames.Add(fileID, &mu)
}

// ReportHostMetadata is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportHostMetadata(_ map[string]string) {}

// ReportHostMetadataBlocking is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportHostMetadataBlocking(_ context.Context,
	_ map[string]string, _ int, _ time.Duration) error {
	return nil
}

// ReportMetrics is a NOP for DatadogReporter.
func (r *DatadogReporter) ReportMetrics(_ uint32, _ []uint32, _ []int64) {}

// Stop triggers a graceful shutdown of DatadogReporter.
func (r *DatadogReporter) Stop() {
	close(r.stopSignal)
}

// GetMetrics returns internal metrics of DatadogReporter.
func (r *DatadogReporter) GetMetrics() reporter.Metrics {
	return reporter.Metrics{}
}

// StartDatadog sets up and manages the reporting connection to the Datadog Backend.
func Start(mainCtx context.Context, cfg *Config, p containermetadata.Provider) (reporter.Reporter, error) {
	executables, err := lru.NewSynced[libpf.FileID, execInfo](cfg.CacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cfg.CacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	processes, err := lru.NewSynced[libpf.PID, processMetadata](cfg.CacheSize, libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}

	var symbolUploader *DatadogSymbolUploader
	if cfg.SymbolUploaderConfig.Enabled {
		log.Infof("Enabling Datadog local symbol upload")
		symbolUploader, err = NewDatadogSymbolUploader(cfg.SymbolUploaderConfig)
		if err != nil {
			log.Errorf(
				"Failed to create Datadog symbol uploader, symbol upload will be disabled: %v",
				err)
		}
	}

	r := &DatadogReporter{
		version:                   cfg.Version,
		samplesPerSecond:          cfg.SamplesPerSecond,
		stopSignal:                make(chan libpf.Void),
		executables:               executables,
		frames:                    frames,
		containerMetadataProvider: p,
		traceEvents:               xsync.NewRWMutex(map[traceAndMetaKey]*traceEvents{}),
		processes:                 processes,
		intakeURL:                 cfg.IntakeURL,
		pprofPrefix:               cfg.PprofPrefix,
		apiKey:                    cfg.APIKey,
		symbolUploader:            symbolUploader,
		tags:                      cfg.Tags,
		timeline:                  cfg.Timeline,
		profileSeq:                0,
	}

	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	if r.symbolUploader != nil {
		go func() {
			r.symbolUploader.Run(ctx)
		}()
	}

	go func() {
		tick := time.NewTicker(cfg.ReportInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.reportProfile(ctx); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(cfg.ReportInterval, 0.2))
			}
		}
	}()

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	go func() {
		<-r.stopSignal
		cancelReporting()
	}()

	return r, nil
}

// reportProfile creates and sends out a profile.
func (r *DatadogReporter) reportProfile(ctx context.Context) error {
	profile, startTS, endTS := r.getPprofProfile()

	if len(profile.Sample) == 0 {
		log.Debugf("Skip sending of pprof profile with no samples")
		return nil
	}

	// serialize the profile to a buffer and send it out
	b := new(bytes.Buffer)
	compressed := zstd.NewWriter(b)
	if err := profile.WriteUncompressed(compressed); err != nil {
		return err
	}
	if err := compressed.Close(); err != nil {
		return fmt.Errorf("failed to compress profile: %w", err)
	}

	if r.pprofPrefix != "" {
		// write profile to disk
		endTime := time.Unix(0, int64(endTS))
		profileName := fmt.Sprintf("%s%s.pprof", r.pprofPrefix, endTime.Format("20060102T150405Z"))
		f, err := os.Create(profileName)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := profile.Write(f); err != nil {
			return err
		}
	}

	tags := r.tags
	customAttributes := []string{"container_id", "container_name", "thread_name", "pod_name"}
	for _, attr := range customAttributes {
		tags = append(tags, Tag{Key: "ddprof.custom_ctx", Value: attr})
	}
	// The profiler_name tag allows us to differentiate the source of the profiles.
	tags = append(tags,
		MakeTag("runtime", "native"),
		MakeTag("remote_symbols", "yes"),
		MakeTag("profiler_name", profilerName),
		MakeTag("profiler_version", r.version),
		MakeTag("cpu_arch", runtime.GOARCH),
		MakeTag("profile_seq", strconv.FormatUint(r.profileSeq, 10)))

	r.profileSeq++

	log.Infof("Tags: %v", tags.String())
	return uploadProfiles(ctx, []profileData{{name: "cpu.pprof", data: b.Bytes()}},
		time.Unix(0, int64(startTS)), time.Unix(0, int64(endTS)), r.intakeURL,
		tags, r.version, r.apiKey)
}

// getPprofProfile returns a pprof profile containing all collected samples up to this moment.
func (r *DatadogReporter) getPprofProfile() (profile *pprofile.Profile,
	startTS uint64, endTS uint64) {
	traceEvents := r.traceEvents.WLock()
	samples := maps.Clone(*traceEvents)
	for key := range *traceEvents {
		delete(*traceEvents, key)
	}
	r.traceEvents.WUnlock(&traceEvents)

	numSamples := len(samples)

	const unknownStr = "UNKNOWN"

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]*pprofile.Function)

	samplingPeriod := 1000000000 / int64(r.samplesPerSecond)
	profile = &pprofile.Profile{
		SampleType: []*pprofile.ValueType{{Type: "cpu-samples", Unit: "count"},
			{Type: "cpu-time", Unit: "nanoseconds"}},
		Sample:            make([]*pprofile.Sample, 0, numSamples),
		PeriodType:        &pprofile.ValueType{Type: "cpu-time", Unit: "nanoseconds"},
		Period:            samplingPeriod,
		DefaultSampleType: "cpu-time",
	}

	fileIDtoMapping := make(map[libpf.FileID]*pprofile.Mapping)
	totalSampleCount := 0

	for traceKey, traceInfo := range samples {
		sample := &pprofile.Sample{}

		for _, ts := range traceInfo.timestamps {
			if ts < startTS || startTS == 0 {
				startTS = ts
				continue
			}
			if ts > endTS {
				endTS = ts
			}
		}

		// Walk every frame of the trace.
		for i := range traceInfo.frameTypes {
			loc := createPProfLocation(profile, uint64(traceInfo.linenos[i]))

			switch frameKind := traceInfo.frameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				if tmpMapping, exists := fileIDtoMapping[traceInfo.files[i]]; exists {
					loc.Mapping = tmpMapping
				} else {
					executionInfo, exists := r.executables.Get(traceInfo.files[i])

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = unknownStr
					var buildID = traceInfo.files[i].StringNoQuotes()
					if exists {
						fileName = executionInfo.fileName
						if executionInfo.buildID != "" {
							buildID = executionInfo.buildID
						}
					}

					tmpMapping := createPprofMapping(profile, uint64(traceInfo.linenos[i]),
						fileName, buildID)
					fileIDtoMapping[traceInfo.files[i]] = tmpMapping
					loc.Mapping = tmpMapping
				}
				line := pprofile.Line{Function: createPprofFunctionEntry(funcMap, profile, "",
					loc.Mapping.File)}
				loc.Line = append(loc.Line, line)
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as Line message:
				line := pprofile.Line{}

				fileIDInfoLock, exists := r.frames.Get(traceInfo.files[i])
				if !exists {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					line.Function = createPprofFunctionEntry(funcMap, profile,
						"UNREPORTED", frameKind.String())
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					if si, exists := (*fileIDInfo)[traceInfo.linenos[i]]; exists {
						line.Line = int64(si.lineNumber)
						line.Function = createPprofFunctionEntry(funcMap, profile,
							si.functionName, si.filePath)
					} else {
						// At this point, we do not have enough information for the frame.
						// Therefore, we report a dummy entry and use the interpreter as filename.
						line.Function = createPprofFunctionEntry(funcMap, profile,
							"UNRESOLVED", frameKind.String())
					}
					fileIDInfoLock.RUnlock(&fileIDInfo)
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol generate a dummy mapping entry.
				loc.Mapping = getDummyMapping(fileIDtoMapping, profile, traceInfo.files[i])
			}
			sample.Location = append(sample.Location, loc)
		}

		processMeta, _ := r.processes.Get(traceKey.pid)
		execPath := processMeta.execPath

		// Check if the last frame is a kernel frame.
		if len(traceInfo.frameTypes) > 0 &&
			traceInfo.frameTypes[len(traceInfo.frameTypes)-1] == libpf.KernelFrame {
			// If the last frame is a kernel frame, we need to add a dummy
			// location with the kernel as the function name.
			execPath = "kernel"
		}
		baseExec := path.Base(execPath)

		if execPath != "" {
			loc := createPProfLocation(profile, 0)
			m := createPprofFunctionEntry(funcMap, profile, baseExec, execPath)
			loc.Line = append(loc.Line, pprofile.Line{Function: m})
			sample.Location = append(sample.Location, loc)
		}

		sample.Label = make(map[string][]string)
		var timestamps []uint64
		if r.timeline {
			timestamps = traceInfo.timestamps
		}
		addTraceLabels(sample.Label, traceKey, processMeta, baseExec, timestamps)

		count := int64(len(traceInfo.timestamps))
		sample.Value = append(sample.Value, count, count*samplingPeriod)
		profile.Sample = append(profile.Sample, sample)
		totalSampleCount += len(traceInfo.timestamps)
	}
	log.Infof("Reporting pprof profile with %d samples from %v to %v",
		totalSampleCount, startTS, endTS)

	profile.DurationNanos = int64(endTS - startTS)
	profile.TimeNanos = int64(startTS)

	profile = profile.Compact()

	return profile, startTS, endTS
}

// createFunctionEntry adds a new function and returns its reference index.
func createPprofFunctionEntry(funcMap map[funcInfo]*pprofile.Function,
	profile *pprofile.Profile,
	name string, fileName string) *pprofile.Function {
	key := funcInfo{
		name:     name,
		fileName: fileName,
	}
	if function, exists := funcMap[key]; exists {
		return function
	}

	idx := uint64(len(profile.Function)) + 1
	function := &pprofile.Function{
		ID:       idx,
		Name:     name,
		Filename: fileName,
	}
	profile.Function = append(profile.Function, function)
	funcMap[key] = function

	return function
}

func addTraceLabels(labels map[string][]string, i traceAndMetaKey, processMeta processMetadata,
	baseExec string, timestamps []uint64) {
	if i.comm != "" {
		labels["thread_name"] = append(labels["thread_name"], i.comm)
	}

	if processMeta.containerMetadata.PodName != "" {
		labels["pod_name"] = append(labels["pod_name"], processMeta.containerMetadata.PodName)
	}

	if processMeta.containerMetadata.ContainerID != "" {
		labels["container_id"] = append(labels["container_id"], processMeta.containerMetadata.ContainerID)
	}

	if processMeta.containerMetadata.ContainerName != "" {
		labels["container_name"] = append(labels["container_name"], processMeta.containerMetadata.ContainerName)
	}

	if i.apmServiceName != "" {
		labels["apmServiceName"] = append(labels["apmServiceName"], i.apmServiceName)
	}

	if i.pid != 0 {
		labels["process_id"] = append(labels["process_id"], fmt.Sprintf("%d", i.pid))
	}

	if i.tid != 0 {
		// The naming has an impact on the backend side,
		// this is why we use "thread id" instead of "thread_id"
		// This is also consistent with ddprof.
		labels["thread id"] = append(labels["thread id"], fmt.Sprintf("%d", i.tid))
	}

	if baseExec != "" {
		labels["process_name"] = append(labels["process_name"], baseExec)
	}

	if len(timestamps) > 0 {
		timestampStrs := make([]string, 0, len(timestamps))
		for _, ts := range timestamps {
			timestampStrs = append(timestampStrs, strconv.FormatUint(ts, 10))
		}
		// Assign all timestamps as a single label entry
		labels["end_timestamp_ns"] = timestampStrs
	}
}

// getDummyMappingIndex inserts or looks up a dummy entry for interpreted FileIDs.
func getDummyMapping(fileIDtoMapping map[libpf.FileID]*pprofile.Mapping,
	profile *pprofile.Profile, fileID libpf.FileID) *pprofile.Mapping {
	if tmpMapping, exists := fileIDtoMapping[fileID]; exists {
		return tmpMapping
	}

	mapping := createPprofMapping(profile, 0, "DUMMY", fileID.StringNoQuotes())
	fileIDtoMapping[fileID] = mapping

	return mapping
}

func createPProfLocation(profile *pprofile.Profile,
	address uint64) *pprofile.Location {
	idx := uint64(len(profile.Location)) + 1
	location := &pprofile.Location{
		ID:      idx,
		Address: address,
	}
	profile.Location = append(profile.Location, location)
	return location
}

func createPprofMapping(profile *pprofile.Profile, offset uint64,
	fileName string, buildID string) *pprofile.Mapping {
	idx := uint64(len(profile.Mapping)) + 1
	mapping := &pprofile.Mapping{
		ID:      idx,
		File:    fileName,
		Offset:  offset,
		BuildID: buildID,
	}
	profile.Mapping = append(profile.Mapping, mapping)
	return mapping
}

func (r *DatadogReporter) addProcessMetadata(pid libpf.PID) {
	execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Debugf("Failed to get process metadata for PID %d: %v", pid, err)
		return
	}
	containerMetadata, err := r.containerMetadataProvider.GetContainerMetadata(pid)
	if err != nil {
		log.Debugf("Failed to get container metadata for PID %d: %v", pid, err)
		// Even upon failure, we might still have managed to get the containerID
	}

	r.processes.Add(pid, processMetadata{execPath, containerMetadata})
}
