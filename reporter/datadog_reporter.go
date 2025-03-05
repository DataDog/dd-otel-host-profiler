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
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"

	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
)

// Assert that we implement the full Reporter interface.
var _ reporter.Reporter = (*DatadogReporter)(nil)

const (
	unknownServiceStr = "unknown-service"
	servicePrefix     = "test-split-"

	profilerName            = "dd-otel-host-profiler"
	pidCacheUpdateInterval  = 1 * time.Minute // pid cache items will be updated at most once per this interval
	pidCacheCleanupInterval = 5 * time.Minute // pid cache items for which metadata hasn't been updated in this interval will be removed
	executableCacheLifetime = 1 * time.Hour   // executable cache items will be removed if unused after this interval

	profileUploadWorkerCount = 5
)

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
	executablePath string
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
	updatedAt         time.Time
	containerMetadata containermetadata.ContainerMetadata
	ddService         string
}

type uploadProfileData struct {
	startTS     uint64
	endTS       uint64
	profile     *pprofile.Profile
	containerID string
	serviceName string
	runtime     string
	family      string
}

// DatadogReporter receives and transforms information to be OTLP/profiles compliant.
type DatadogReporter struct {
	config *Config

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

	profiles chan uploadProfileData
}

func NewDatadog(cfg *Config, p containermetadata.Provider) (*DatadogReporter, error) {
	executables, err := lru.NewSynced[libpf.FileID, execInfo](cfg.ExecutablesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	executables.SetLifetime(executableCacheLifetime)

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cfg.FramesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	// TODO: Consider purging stale entries from frames to avoid memory leaks.
	// Currently, setting a lifetime via go-freelru will cause the frames to be
	// removed from the cache after the lifetime expires, regardless of whether
	// they are still in use or not.
	// This leads to mappings missing function name information, which is
	// required for the profile to be correctly displayed in the Datadog UI.

	processes, err := lru.NewSynced[libpf.PID, processMetadata](cfg.ProcessesCacheElements, libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}
	processes.SetLifetime(pidCacheCleanupInterval)

	var symbolUploader *DatadogSymbolUploader
	if cfg.SymbolUploaderConfig.Enabled {
		log.Infof("Enabling Datadog local symbol upload")
		symbolUploader, err = NewDatadogSymbolUploader(&cfg.SymbolUploaderConfig)
		if err != nil {
			log.Errorf(
				"Failed to create Datadog symbol uploader, symbol upload will be disabled: %v",
				err)
		}
	}

	return &DatadogReporter{
		config:                    cfg,
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
		profiles:                  make(chan uploadProfileData, 15),
	}, nil
}

// SupportsReportTraceEvent returns true if the reporter supports reporting trace events
// via ReportTraceEvent().
func (r *DatadogReporter) SupportsReportTraceEvent() bool {
	return true
}

// ReportTraceEvent enqueues reported trace events for the Datadog reporter.
func (r *DatadogReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	traceEventsMap := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEventsMap)

	if pMeta, ok := r.processes.Get(meta.PID); !ok || time.Since(pMeta.updatedAt) > pidCacheUpdateInterval {
		r.addProcessMetadata(meta.PID)
	}

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           meta.Comm,
		apmServiceName: meta.APMServiceName,
		pid:            meta.PID,
		tid:            meta.TID,
		executablePath: meta.ExecutablePath,
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
func (r *DatadogReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *samples.TraceEventMeta) {
}

// ExecutableKnown returns true if the metadata of the Executable specified by fileID is
// cached in the reporter.
func (r *DatadogReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := r.executables.Get(fileID)
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *DatadogReporter) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {
	r.executables.Add(args.FileID, execInfo{
		fileName: path.Base(args.FileName),
		buildID:  args.GnuBuildID,
	})

	if r.symbolUploader != nil && args.Interp == libpf.Native {
		r.symbolUploader.UploadSymbols(args.FileID, args.FileName, args.GnuBuildID, args.Open)
	}
}

// FrameKnown returns true if the metadata of the Frame specified by frameID is
// cached in the reporter.
func (r *DatadogReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := r.frames.Get(frameID.FileID()); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *DatadogReporter) FrameMetadata(args *reporter.FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	log.Debugf("FrameMetadata [%x] %v+%v at %v:%v",
		fileID, args.FunctionName, args.FunctionOffset,
		args.SourceFile, args.SourceLine)

	if frameMapLock, exists := r.frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		sourceFile := args.SourceFile

		if sourceFile == "" {
			// The new sourceFile may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				sourceFile = s.filePath
			}
		}

		(*frameMap)[addressOrLine] = sourceInfo{
			lineNumber:     args.SourceLine,
			filePath:       sourceFile,
			functionOffset: args.FunctionOffset,
			functionName:   args.FunctionName,
		}

		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     args.SourceLine,
		filePath:       args.SourceFile,
		functionOffset: args.FunctionOffset,
		functionName:   args.FunctionName,
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

// Start sets up and manages the reporting connection to the Datadog Backend.
func (r *DatadogReporter) Start(mainCtx context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	if r.symbolUploader != nil {
		go func() {
			r.symbolUploader.Run(ctx)
		}()
	}

	go func() {
		tick := time.NewTicker(r.config.ReportInterval)
		defer tick.Stop()
		purgeTick := time.NewTicker(5 * time.Minute)
		defer purgeTick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopSignal:
				return
			case <-tick.C:
				r.getPprofProfile()

				tick.Reset(libpf.AddJitter(r.config.ReportInterval, 0.2))
			case <-purgeTick.C:
				// Allow the GC to purge expired entries to avoid memory leaks.
				r.executables.PurgeExpired()
				r.frames.PurgeExpired()
				r.processes.PurgeExpired()
			}
		}
	}()

	for i := 0; i < profileUploadWorkerCount; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-r.stopSignal:
					return
				case profile := <-r.profiles:
					if err := r.reportProfile(ctx, profile); err != nil {
						log.Errorf("Request failed: %v", err)
					}
				}
			}
		}()
	}

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	go func() {
		<-r.stopSignal
		cancelReporting()
	}()

	return nil
}

// reportProfile creates and sends out a profile.
func (r *DatadogReporter) reportProfile(ctx context.Context, data uploadProfileData) error {
	profile := data.profile
	startTS := data.startTS
	endTS := data.endTS

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
		MakeTag("runtime", data.runtime),
		MakeTag("remote_symbols", "yes"),
		MakeTag("profiler_name", profilerName),
		MakeTag("profiler_version", r.version),
		MakeTag("cpu_arch", runtime.GOARCH),
		MakeTag("profile_seq", strconv.FormatUint(r.profileSeq, 10)),
		MakeTag("service", servicePrefix+data.serviceName))

	r.profileSeq++

	log.Infof("Tags: %v", tags.String())
	return uploadProfiles(ctx, []profileData{{name: "cpu.pprof", data: b.Bytes()}},
		time.Unix(0, int64(startTS)), time.Unix(0, int64(endTS)), r.intakeURL,
		tags, r.version, r.apiKey, data.containerID, data.family)
}

// getPprofProfile returns a pprof profile containing all collected samples up to this moment.
func (r *DatadogReporter) getPprofProfile() {
	events := r.traceEvents.WLock()
	hostSamples := maps.Clone(*events)
	for key := range *events {
		delete(*events, key)
	}
	r.traceEvents.WUnlock(&events)

	type entity struct {
		service     string
		containerID string
	}

	entityToSample := make(map[entity]map[traceAndMetaKey]*traceEvents)
	startTS, endTS := uint64(0), uint64(0)

	for traceKey, traceInfo := range hostSamples {
		processMeta, ok := r.processes.Get(traceKey.pid)
		if !ok {
			log.Infof("No process metadata found for PID %d", traceKey.pid)
		}

		containerID := processMeta.containerMetadata.ContainerID
		service := processMeta.ddService

		if service == "" && traceKey.executablePath != "" && traceKey.executablePath != "/" {
			service = path.Base(traceKey.executablePath)
		}

		if service == "" && len(traceInfo.frameTypes) > 0 &&
			traceInfo.frameTypes[len(traceInfo.frameTypes)-1] == libpf.KernelFrame {
			service = "system"
		}

		if service == "" {
			service = unknownServiceStr
		}

		if _, exists := entityToSample[entity{service, containerID}]; !exists {
			entityToSample[entity{service, containerID}] = make(map[traceAndMetaKey]*traceEvents)
		}

		entityToSample[entity{service, containerID}][traceKey] = traceInfo

		for _, ts := range traceInfo.timestamps {
			if ts < startTS || startTS == 0 {
				startTS = ts
				continue
			}
			if ts > endTS {
				endTS = ts
			}
		}
	}

	for e, s := range entityToSample {
		numSamples := len(s)

		const unknownStr = "UNKNOWN"

		// funcMap is a temporary helper that will build the Function array
		// in profile and make sure information is deduplicated.
		funcMap := make(map[funcInfo]*pprofile.Function)

		samplingPeriod := 1000000000 / int64(r.samplesPerSecond)
		profile := &pprofile.Profile{
			SampleType: []*pprofile.ValueType{{Type: "cpu-samples", Unit: "count"},
				{Type: "cpu-time", Unit: "nanoseconds"}},
			Sample:            make([]*pprofile.Sample, 0, numSamples),
			PeriodType:        &pprofile.ValueType{Type: "cpu-time", Unit: "nanoseconds"},
			Period:            samplingPeriod,
			DefaultSampleType: "cpu-time",
		}

		fileIDtoMapping := make(map[libpf.FileID]*pprofile.Mapping)
		totalSampleCount := 0
		var sampleRuntime string
		var sampleFamily string
		for traceKey, traceInfo := range s {
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
						executionInfo, exists := r.executables.GetAndRefresh(traceInfo.files[i], executableCacheLifetime)

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

			if len(sampleRuntime) == 0 && len(traceInfo.frameTypes) > 0 {
				sampleRuntime = frameTypeToRuntime(traceInfo.frameTypes[len(traceInfo.frameTypes)-1])
			}

			if len(sampleFamily) == 0 && len(traceInfo.frameTypes) > 0 {
				sampleFamily = frameTypeToFamily(traceInfo.frameTypes[len(traceInfo.frameTypes)-1])
			}

			processMeta, _ := r.processes.Get(traceKey.pid)
			execPath := traceKey.executablePath

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

			if !r.timeline {
				count := int64(len(traceInfo.timestamps))
				labels := make(map[string][]string)
				addTraceLabels(labels, traceKey, processMeta.containerMetadata, baseExec, 0)
				sample.Value = append(sample.Value, count, count*samplingPeriod)
				sample.Label = labels
				profile.Sample = append(profile.Sample, sample)
			} else {
				sample.Value = append(sample.Value, 1, samplingPeriod)
				for _, ts := range traceInfo.timestamps {
					sampleWithTimestamp := &pprofile.Sample{}
					*sampleWithTimestamp = *sample
					labels := make(map[string][]string)
					addTraceLabels(labels, traceKey, processMeta.containerMetadata, baseExec, ts)
					sampleWithTimestamp.Label = labels
					profile.Sample = append(profile.Sample, sampleWithTimestamp)
				}
			}
			totalSampleCount += len(traceInfo.timestamps)
		}

		log.Infof("Reporting pprof profile with %d samples from %v to %v",
			totalSampleCount, startTS, endTS)

		profile.DurationNanos = int64(endTS - startTS)
		profile.TimeNanos = int64(startTS)

		profile = profile.Compact()

		select {
		case r.profiles <- uploadProfileData{
			profile:     profile,
			startTS:     startTS,
			endTS:       endTS,
			serviceName: e.service,
			containerID: e.containerID,
			runtime:     sampleRuntime,
			family:      sampleFamily,
		}:
		default:
			log.Warnf("Dropping profile data")
		}
	}
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

func addTraceLabels(labels map[string][]string, i traceAndMetaKey, containerMetadata containermetadata.ContainerMetadata,
	baseExec string, timestamp uint64) {
	if i.comm != "" {
		labels["thread_name"] = append(labels["thread_name"], i.comm)
	}

	if containerMetadata.PodName != "" {
		labels["pod_name"] = append(labels["pod_name"], containerMetadata.PodName)
	}

	if containerMetadata.ContainerID != "" {
		labels["container_id"] = append(labels["container_id"], containerMetadata.ContainerID)
	}

	if containerMetadata.ContainerName != "" {
		labels["container_name"] = append(labels["container_name"], containerMetadata.ContainerName)
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

	if timestamp != 0 {
		labels["end_timestamp_ns"] = append(labels["end_timestamp_ns"], strconv.FormatUint(timestamp, 10))
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
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		log.Debugf("Failed to get process metadata for PID %d: %v", pid, err)
		return
	}

	containerMetadata, err := r.containerMetadataProvider.GetContainerMetadata(pid)
	if err != nil {
		log.Infof("Failed to get container metadata for PID %d: %v", pid, err)
		// Even upon failure, we might still have managed to get the containerID
	}

	// read DD_SERVICE env var from the process environ
	envPath, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		log.Debugf("Failed to read environ for PID %d: %v", pid, err)
	}

	ddService := ""
	for _, envVar := range bytes.Split(envPath, []byte{0}) {
		if bytes.HasPrefix(envVar, []byte("DD_SERVICE=")) {
			ddService = string(envVar[11:])
			break
		}
	}

	r.processes.Add(pid, processMetadata{
		updatedAt:         time.Now(),
		containerMetadata: containerMetadata,
		ddService:         ddService,
	})
}

func frameTypeToRuntime(frameType libpf.FrameType) string {
	def := "native"

	switch frameType {
	case libpf.NativeFrame:
		return def
	case libpf.KernelFrame:
		return def
	case libpf.HotSpotFrame:
		return "jvm"
	case libpf.PHPFrame:
		return "zendengine"
	case libpf.V8Frame:
		return "nodejs"
	case libpf.PythonFrame:
		return "CPython"
	case libpf.RubyFrame:
		return "ruby"
	case libpf.DotnetFrame:
		return "dotnet"

	default:
		return def
	}
}

func frameTypeToFamily(frameType libpf.FrameType) string {
	def := "native"

	switch frameType {
	case libpf.NativeFrame:
		return def
	case libpf.KernelFrame:
		return def
	case libpf.HotSpotFrame:
		return "java"
	case libpf.PHPFrame:
		return "php"
	case libpf.V8Frame:
		return "node"
	case libpf.PythonFrame:
		return "python"
	case libpf.RubyFrame:
		return "ruby"
	case libpf.DotnetFrame:
		return "dotnet"

	default:
		return def
	}
}
