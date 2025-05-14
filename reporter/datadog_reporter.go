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

	profilerName            = "dd-otel-host-profiler"
	pidCacheUpdateInterval  = 1 * time.Minute // pid cache items will be updated at most once per this interval
	pidCacheCleanupInterval = 5 * time.Minute // pid cache items for which metadata hasn't been updated in this interval will be removed
	executableCacheLifetime = 1 * time.Hour   // executable cache items will be removed if unused after this interval
	framesCacheLifetime     = 1 * time.Hour   // frames cache items will be removed if unused after this interval

	profileUploadWorkerCount = 5
	profileUploadQueueSize   = 128
)

// execInfo enriches an executable with additional metadata.
type execInfo struct {
	fileName   string
	gnuBuildID string
	goBuildID  string
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
	executablePath string
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
	ddService          string
}

type processMetadata struct {
	updatedAt         time.Time
	executablePath    string
	containerMetadata containermetadata.ContainerMetadata
}

type uploadProfileData struct {
	start       time.Time
	end         time.Time
	profile     *pprofile.Profile
	containerID string
	entityID    string
	tags        Tags
}

type serviceEntity struct {
	service         string
	containerID     string
	entityID        string
	inferredService bool
}

type profileStats struct {
	totalSampleCount  int
	pidWithNoMetadata int
}

// DatadogReporter receives and transforms information to be OTLP/profiles compliant.
type DatadogReporter struct {
	config *Config

	// runLoop handles the run loop
	runLoop *runLoop

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

	symbolUploader *DatadogSymbolUploader

	containerMetadataProvider containermetadata.Provider

	// tags is the list of tags to be added to the profile.
	tags Tags

	// family is the family of the profiler.
	family string

	// profileSeq is the sequence number of the profile (ie. number of profiles uploaded until now).
	profileSeq uint64

	// intervalStart is the timestamp of the start of the current interval.
	intervalStart time.Time

	profiles chan *uploadProfileData
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
	frames.SetLifetime(framesCacheLifetime)
	// Using SetLifetime / GetAndRefresh on frames prevents useful information from being
	// evicted from the cache.
	// But it also means that active frames will never be evicted, and thus that their corresponding values
	// (which are maps) may grow indefinitely (cf. https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/260).

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

	runtimeTag, family := "ebpf", "ebpf"

	return &DatadogReporter{
		config: cfg,
		runLoop: &runLoop{
			stopSignal: make(chan libpf.Void),
		},
		executables:               executables,
		frames:                    frames,
		containerMetadataProvider: p,
		traceEvents:               xsync.NewRWMutex(map[traceAndMetaKey]*traceEvents{}),
		processes:                 processes,
		symbolUploader:            symbolUploader,
		tags:                      createTags(cfg.Tags, runtimeTag, cfg.Version, cfg.EnableSplitByService),
		family:                    family,
		profileSeq:                0,
		profiles:                  make(chan *uploadProfileData, profileUploadQueueSize),
	}, nil
}

// ReportTraceEvent enqueues reported trace events for the Datadog reporter.
func (r *DatadogReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	traceEventsMap := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEventsMap)

	if pMeta, ok := r.processes.Get(meta.PID); !ok || time.Since(pMeta.updatedAt) > pidCacheUpdateInterval {
		r.addProcessMetadata(meta.PID)
	}

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           meta.Comm,
		executablePath: meta.ExecutablePath,
		apmServiceName: meta.APMServiceName,
		pid:            meta.PID,
		tid:            meta.TID,
	}

	if tr, exists := (*traceEventsMap)[key]; exists {
		tr.timestamps = append(tr.timestamps, uint64(meta.Timestamp))
		(*traceEventsMap)[key] = tr
		return nil
	}

	(*traceEventsMap)[key] = &traceEvents{
		files:              trace.Files,
		linenos:            trace.Linenos,
		frameTypes:         trace.FrameTypes,
		mappingStarts:      trace.MappingStart,
		mappingEnds:        trace.MappingEnd,
		mappingFileOffsets: trace.MappingFileOffsets,
		timestamps:         []uint64{uint64(meta.Timestamp)},
		ddService:          meta.EnvVars["DD_SERVICE"],
	}

	return nil
}

// ExecutableKnown returns true if the metadata of the Executable specified by fileID is
// cached in the reporter.
func (r *DatadogReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := r.executables.GetAndRefresh(fileID, executableCacheLifetime)
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *DatadogReporter) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {
	r.executables.Add(args.FileID, execInfo{
		fileName:   path.Base(args.FileName),
		gnuBuildID: args.GnuBuildID,
		goBuildID:  args.GoBuildID,
	})

	if r.symbolUploader != nil && args.Interp == libpf.Native {
		r.symbolUploader.UploadSymbols(args.FileID, args.FileName, args.GnuBuildID, args.Open)
	}
}

// FrameKnown returns true if the metadata of the Frame specified by frameID is
// cached in the reporter.
func (r *DatadogReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := r.frames.GetAndRefresh(frameID.FileID(), framesCacheLifetime); exists {
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

	if frameMapLock, exists := r.frames.GetAndRefresh(fileID, framesCacheLifetime); exists {
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

// Stop triggers a graceful shutdown of DatadogReporter.
func (r *DatadogReporter) Stop() {
	r.runLoop.Stop()
}

// Start sets up and manages the reporting connection to the Datadog Backend.
func (r *DatadogReporter) Start(mainCtx context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	if r.symbolUploader != nil {
		r.symbolUploader.Start(ctx)
	}

	r.intervalStart = time.Now()

	r.runLoop.Start(ctx, r.config.ReportInterval, func() {
		r.getPprofProfile()
	}, func() {
		// Allow the GC to purge expired entries to avoid memory leaks.
		r.executables.PurgeExpired()
		r.frames.PurgeExpired()
		r.processes.PurgeExpired()
	})

	for range profileUploadWorkerCount {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-r.runLoop.stopSignal:
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
		<-r.runLoop.stopSignal
		cancelReporting()
	}()

	return nil
}

// reportProfile creates and sends out a profile.
func (r *DatadogReporter) reportProfile(ctx context.Context, data *uploadProfileData) error {
	profile := data.profile

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

	if r.config.PprofPrefix != "" {
		// write profile to disk
		profileName := fmt.Sprintf("%s%s.pprof", r.config.PprofPrefix, data.end.Format("20060102T150405Z"))
		f, err := os.Create(profileName)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := profile.Write(f); err != nil {
			return err
		}
	}

	return uploadProfiles(ctx, []profileData{{name: "cpu.pprof", data: b.Bytes()}},
		data.start, data.end, r.config.IntakeURL,
		data.tags, r.config.Version, r.config.APIKey,
		data.containerID, data.entityID, r.family)
}

func (r *DatadogReporter) createProfile(hostSamples map[traceAndMetaKey]*traceEvents, start, end time.Time) (*pprofile.Profile, profileStats) {
	numSamples := len(hostSamples)

	const unknownStr = "UNKNOWN"

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]*pprofile.Function)

	samplingPeriod := 1000000000 / int64(r.config.SamplesPerSecond)
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
	pidsWithNoProcessMetadata := libpf.Set[libpf.PID]{}
	for traceKey, traceInfo := range hostSamples {
		sample := &pprofile.Sample{}

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
						buildID = getBuildID(executionInfo.gnuBuildID, executionInfo.goBuildID, buildID)
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

				fileIDInfoLock, exists := r.frames.GetAndRefresh(traceInfo.files[i], framesCacheLifetime)
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

		processMeta, ok := r.processes.Get(traceKey.pid)
		if !ok {
			pidsWithNoProcessMetadata[traceKey.pid] = libpf.Void{}
		}
		execPath := getExecutablePath(&processMeta, &traceKey)

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

		containerMetadata := containermetadata.ContainerMetadata{}
		if !r.config.EnableSplitByService {
			containerMetadata = processMeta.containerMetadata
		}
		if !r.config.Timeline {
			count := int64(len(traceInfo.timestamps))
			labels := make(map[string][]string)
			addTraceLabels(labels, traceKey, containerMetadata, baseExec, 0)
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

	profile.DurationNanos = end.Sub(start).Nanoseconds()
	profile.TimeNanos = start.UnixNano()

	profile = profile.Compact()

	return profile, profileStats{
		totalSampleCount:  totalSampleCount,
		pidWithNoMetadata: len(pidsWithNoProcessMetadata),
	}
}

// getPprofProfile returns a pprof profile containing all collected samples up to this moment.
func (r *DatadogReporter) getPprofProfile() {
	intervalEnd := time.Now()
	intervalStart := r.intervalStart
	r.intervalStart = intervalEnd
	profileSeq := r.profileSeq
	r.profileSeq++

	events := r.traceEvents.WLock()
	hostSamples := maps.Clone(*events)
	for key := range *events {
		delete(*events, key)
	}
	r.traceEvents.WUnlock(&events)

	entityToSample := make(map[serviceEntity]map[traceAndMetaKey]*traceEvents)

	if !r.config.EnableSplitByService {
		profile, stats := r.createProfile(hostSamples, intervalStart, intervalEnd)

		tags := createTagsForProfile(r.tags, profileSeq, r.config.HostServiceName, false)
		r.profiles <- &uploadProfileData{
			profile: profile,
			start:   intervalStart,
			end:     intervalEnd,
			tags:    tags,
		}
		log.Infof("Tags: %v", tags)
		log.Infof("Reporting single profile #%d from %v to %v: %d samples, %d PIDs with no process metadata",
			profileSeq, intervalStart.Format(time.RFC3339), intervalEnd.Format(time.RFC3339), stats.totalSampleCount, stats.pidWithNoMetadata)
		return
	}

	for traceKey, traceInfo := range hostSamples {
		processMeta, _ := r.processes.Get(traceKey.pid)

		service := traceInfo.ddService
		execPath := getExecutablePath(&processMeta, &traceKey)
		inferredService := false

		if service == "" && execPath != "" && execPath != "/" {
			service = path.Base(execPath)
			inferredService = true
		}

		if service == "" && len(traceInfo.frameTypes) > 0 &&
			traceInfo.frameTypes[len(traceInfo.frameTypes)-1] == libpf.KernelFrame {
			service = "system"
			inferredService = true
		}

		if service == "" {
			service = unknownServiceStr
			inferredService = true
		}

		entity := serviceEntity{
			service:         service + r.config.SplitServiceSuffix,
			containerID:     processMeta.containerMetadata.ContainerID,
			entityID:        processMeta.containerMetadata.EntityID,
			inferredService: inferredService,
		}
		serviceSamples, exists := entityToSample[entity]
		if !exists {
			serviceSamples = make(map[traceAndMetaKey]*traceEvents)
			entityToSample[entity] = serviceSamples
		}

		serviceSamples[traceKey] = traceInfo
	}

	totalSampleCount := 0
	totalPIDsWithNoProcessMetadata := 0
	for e, s := range entityToSample {
		profile, stats := r.createProfile(s, intervalStart, intervalEnd)
		totalSampleCount += stats.totalSampleCount
		totalPIDsWithNoProcessMetadata += stats.pidWithNoMetadata
		tags := createTagsForProfile(r.tags, profileSeq, e.service, e.inferredService)
		r.profiles <- &uploadProfileData{
			profile:     profile,
			start:       intervalStart,
			end:         intervalEnd,
			containerID: e.containerID,
			entityID:    e.entityID,
			tags:        tags,
		}
		log.Debugf("Reporting profile for service %s: %d samples, %d PIDs with no process metadata, tags: %v", e.service, stats.totalSampleCount, stats.pidWithNoMetadata, tags)
	}
	log.Infof("Reporting %d profiles #%d from %v to %v: %d samples, %d PIDs with no process metadata",
		len(entityToSample), profileSeq, intervalStart.Format(time.RFC3339), intervalEnd.Format(time.RFC3339), totalSampleCount, totalPIDsWithNoProcessMetadata)
}

func createTags(userTags Tags, runtimeTag, version string, splitByServiceEnabled bool) Tags {
	tags := append(Tags{}, userTags...)

	if !splitByServiceEnabled {
		customContextTagKey := "ddprof.custom_ctx"

		tags = append(tags,
			MakeTag(customContextTagKey, "container_id"),
			MakeTag(customContextTagKey, "container_name"),
			MakeTag(customContextTagKey, "pod_name"),
		)
	}

	tags = append(tags,
		MakeTag("runtime", runtimeTag),
		MakeTag("remote_symbols", "yes"),
		MakeTag("profiler_name", profilerName),
		MakeTag("profiler_version", version),
		MakeTag("cpu_arch", runtime.GOARCH))

	return tags
}

func createTagsForProfile(tags Tags, profileSeq uint64, service string, inferredService bool) Tags {
	newTags := append(Tags{}, tags...)
	newTags = append(newTags,
		MakeTag("profile_seq", strconv.FormatUint(profileSeq, 10)),
		MakeTag("service", service))
	if inferredService {
		newTags = append(newTags, MakeTag("service_inferred", "yes"))
	}
	return newTags
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
		// The naming has an impact on the backend side,
		// this is why we use "thread name" instead of "thread_name"
		labels["thread name"] = append(labels["thread name"], i.comm)
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

func getBuildID(gnuBuildID, goBuildID, fileHash string) string {
	// When building Go binaries, Bazel will set the Go build ID to "redacted" to
	// achieve deterministic builds. Since Go 1.24, the Gnu Build ID is inherited
	// from the Go build ID - if the Go build ID is "redacted", the Gnu Build ID will
	// be a hash of "redacted". In this case, we should use the file hash instead of build IDs.
	if goBuildID == "redacted" {
		return fileHash
	}
	if gnuBuildID != "" {
		return gnuBuildID
	}
	if goBuildID != "" {
		return goBuildID
	}
	return fileHash
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

	r.processes.Add(pid, processMetadata{
		updatedAt:         time.Now(),
		executablePath:    execPath,
		containerMetadata: containerMetadata,
	})
}

func getExecutablePath(processMeta *processMetadata, traceKey *traceAndMetaKey) string {
	if processMeta.executablePath != "" {
		// If we were unable to get the process metadata, we use the executable path
		// from the trace key.
		// This can happen if the process has already exited when process metadata
		// was collected.
		// We prioritize the executable path from process metadata over the trace key
		// because in some cases executable path from trace key is taken too early in
		// the process lifetime, eg. before the process execs into another binary.
		return processMeta.executablePath
	}
	return traceKey.executablePath
}
