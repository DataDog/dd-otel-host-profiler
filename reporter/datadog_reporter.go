// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/DataDog/dd-otel-host-profiler/containermetadata"
)

// Assert that we implement the full Reporter interface.
var _ reporter.Reporter = (*DatadogReporter)(nil)
var errUnknownOrigin = errors.New("unknown trace origin")

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

var ServiceNameEnvVars = []string{"DD_SERVICE", "OTEL_SERVICE_NAME"}

// execInfo enriches an executable with additional metadata.
type execInfo struct {
	fileName   string
	gnuBuildID string
	goBuildID  string
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

type processMetadata struct {
	updatedAt         time.Time
	executablePath    string
	containerMetadata containermetadata.ContainerMetadata
	service           string
	inferredService   bool
}

type uploadProfileData struct {
	start    time.Time
	end      time.Time
	profile  *pprofile.Profile
	entityID string
	tags     Tags
}

type serviceEntity struct {
	service         string
	entityID        string
	inferredService bool
}

type profileStats struct {
	totalSampleCount  int
	pidWithNoMetadata int
}

type traceEventsTree map[serviceEntity]map[libpf.Origin]keyToEventMapping

type keyToEventMapping map[traceAndMetaKey]*samples.TraceEvents

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

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[traceEventsTree]

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
		containerMetadataProvider: p,
		traceEvents:               xsync.NewRWMutex(make(traceEventsTree)),
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
	if meta.Origin != support.TraceOriginSampling && meta.Origin != support.TraceOriginOffCPU {
		// At the moment only on-CPU and off-CPU traces are reported.
		return fmt.Errorf("skip reporting trace for %d origin: %w", meta.Origin,
			errUnknownOrigin)
	}

	pMeta, ok := r.processes.Get(meta.PID)
	if !ok || time.Since(pMeta.updatedAt) > pidCacheUpdateInterval {
		pMeta = r.addProcessMetadata(trace, meta)
	}

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           meta.Comm,
		executablePath: meta.ExecutablePath,
		apmServiceName: meta.APMServiceName,
		pid:            meta.PID,
		tid:            meta.TID,
	}

	eventsTree := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&eventsTree)

	serviceEntityKey := serviceEntity{
		service:         pMeta.service,
		entityID:        pMeta.containerMetadata.EntityID,
		inferredService: pMeta.inferredService,
	}

	perServiceEvents, exists := (*eventsTree)[serviceEntityKey]
	if !exists {
		perServiceEvents = make(map[libpf.Origin]keyToEventMapping)
		(*eventsTree)[serviceEntityKey] = perServiceEvents
	}

	perOriginEvents, exists := perServiceEvents[meta.Origin]
	if !exists {
		perOriginEvents = make(keyToEventMapping)
		perServiceEvents[meta.Origin] = perOriginEvents
	}

	if events, exists := perOriginEvents[key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.OffTimes = append(events.OffTimes, meta.OffTime)
		perOriginEvents[key] = events
		return nil
	}

	perOriginEvents[key] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{uint64(meta.Timestamp)},
		OffTimes:   []int64{meta.OffTime},
		EnvVars:    meta.EnvVars,
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
		data.entityID, r.family)
}

// getPprofProfile returns a pprof profile containing all collected samples up to this moment.
func (r *DatadogReporter) getPprofProfile() {
	intervalEnd := time.Now()
	intervalStart := r.intervalStart
	r.intervalStart = intervalEnd
	profileSeq := r.profileSeq
	r.profileSeq++

	events := r.traceEvents.WLock()
	reportedEvents := *events
	newEvents := make(traceEventsTree)
	*events = newEvents
	r.traceEvents.WUnlock(&events)

	if !r.config.EnableSplitByService {
		profileBuilder := newProfileBuilder(intervalStart, intervalEnd, r.config.SamplesPerSecond, len(reportedEvents), r.config.Timeline, r.executables, r.processes)

		for _, events := range reportedEvents {
			profileBuilder.addEvents(events[support.TraceOriginSampling])
		}
		profile, stats := profileBuilder.build()

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

	totalSampleCount := 0
	totalPIDsWithNoProcessMetadata := 0
	for e, perServiceEvents := range reportedEvents {
		profileBuilder := newProfileBuilder(intervalStart, intervalEnd, r.config.SamplesPerSecond, len(reportedEvents), r.config.Timeline, r.executables, r.processes)

		profileBuilder.addEvents(perServiceEvents[support.TraceOriginSampling])
		profile, stats := profileBuilder.build()
		totalSampleCount += stats.totalSampleCount
		totalPIDsWithNoProcessMetadata += stats.pidWithNoMetadata
		tags := createTagsForProfile(r.tags, profileSeq, e.service, e.inferredService)
		r.profiles <- &uploadProfileData{
			profile:  profile,
			start:    intervalStart,
			end:      intervalEnd,
			entityID: e.entityID,
			tags:     tags,
		}
		log.Debugf("Reporting profile for service %s: %d samples, %d PIDs with no process metadata, tags: %v", e.service, stats.totalSampleCount, stats.pidWithNoMetadata, tags)
	}
	log.Infof("Reporting %d profiles #%d from %v to %v: %d samples, %d PIDs with no process metadata",
		len(reportedEvents), profileSeq, intervalStart.Format(time.RFC3339), intervalEnd.Format(time.RFC3339), totalSampleCount, totalPIDsWithNoProcessMetadata)
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
	inferredServiceTag := "no"
	if inferredService {
		inferredServiceTag = "yes"
	}
	newTags = append(newTags, MakeTag("service_inferred", inferredServiceTag))
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
	// The naming has an impact on the backend side,
	// this is why we use "thread id", "thread name" and "process name"
	if i.tid != 0 {
		labels["thread id"] = append(labels["thread id"], fmt.Sprintf("%d", i.tid))
	}

	if i.comm != "" {
		labels["thread name"] = append(labels["thread name"], i.comm)
	}

	if baseExec != "" {
		labels["process name"] = append(labels["process name"], baseExec)
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

	if i.apmServiceName != "" {
		labels["apmServiceName"] = append(labels["apmServiceName"], i.apmServiceName)
	}

	if i.pid != 0 {
		labels["process_id"] = append(labels["process_id"], fmt.Sprintf("%d", i.pid))
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

func (r *DatadogReporter) addProcessMetadata(trace *libpf.Trace, meta *samples.TraceEventMeta) processMetadata {
	pid := meta.PID
	execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Debugf("Failed to get process metadata for PID %d: %v", pid, err)
		execPath = meta.ExecutablePath
	}

	var service string
	var ok bool
	for _, envVarName := range ServiceNameEnvVars {
		service, ok = meta.EnvVars[envVarName]
		if ok {
			break
		}
	}

	// If DD_SERVICE is not set and the executable path is different from the one in the trace
	// (meaning the process has probably exec'd into another binary)
	// then attempt to retrieve again DD_SERVICE.
	// This can occur when a container is started, during startup the process is runc
	// (without the final container environment) that then execs into the final binary
	// with the container environment.
	if !ok && meta.ExecutablePath != execPath {
		service = getServiceName(pid)
	}

	inferredService := false
	if service == "" && execPath != "" && execPath != "/" {
		service = path.Base(execPath)
		inferredService = true
	}

	if service == "" && isKernel(trace.Frames) {
		service = "system"
	}

	if service == "" {
		service = unknownServiceStr
		inferredService = true
	}

	var containerMetadata containermetadata.ContainerMetadata
	if meta.ContainerID != "" && r.config.EnableSplitByService {
		// Use containerID when found by the eBPF profiler and not other container metadata is needed
		// (ie. split by service is enabled).
		// eBPF profiler only supports cgroup v2 and even with cgroup v2, depending on Kubernetes settings,
		// containerID might not be available in /proc/<pid>/cgroup.
		containerMetadata = containermetadata.ContainerMetadata{
			EntityID: "ci-" + meta.ContainerID,
		}
	} else {
		containerMetadata, err = r.containerMetadataProvider.GetContainerMetadata(pid)
		if err != nil {
			log.Debugf("Failed to get container metadata for PID %d: %v", pid, err)
			// Even upon failure, we might still have managed to get the containerID
		}
	}

	pMeta := processMetadata{
		updatedAt:         time.Now(),
		executablePath:    execPath,
		containerMetadata: containerMetadata,
		service:           service,
		inferredService:   inferredService,
	}
	r.processes.Add(pid, pMeta)
	return pMeta
}

func getServiceNameFromProcPath(pid libpf.PID, procRoot string) string {
	envData, err := os.ReadFile(fmt.Sprintf("%s/proc/%d/environ", procRoot, pid))
	if err != nil {
		log.Debugf("Failed to read environ for PID %d: %v", pid, err)
		return ""
	}

	return parseServiceNameFromEnvironData(envData)
}

// The order in `ServiceNameEnvVars` indicates which environment variable takes precedence.
// For example, if a service sets both DD_SERVICE and OTEL_SERVICE_NAME, DD_SERVICE will
// take precedence.
func parseServiceNameFromEnvironData(envData []byte) string {
	var serviceName string
	foundIndex := len(ServiceNameEnvVars)
	for _, envVar := range bytes.Split(envData, []byte{0}) {
		for i, envVarName := range ServiceNameEnvVars {
			l := len(envVarName)
			if len(envVar) > l+1 && envVar[l] == '=' && bytes.HasPrefix(envVar, []byte(envVarName)) {
				if i < foundIndex {
					serviceName = string(envVar[l+1:])
					foundIndex = i
				}
				if i == 0 {
					return serviceName
				}
			}
		}
	}
	return serviceName
}

func getServiceName(pid libpf.PID) string {
	return getServiceNameFromProcPath(pid, "")
}

func isKernel(frames libpf.Frames) bool {
	if len(frames) == 0 {
		return false
	}

	return frames[len(frames)-1].Value().Type == libpf.KernelFrame
}

type profileBuilder struct {
	profile            *pprofile.Profile
	funcMap            map[funcInfo]*pprofile.Function
	fileIDtoMapping    map[libpf.FileID]*pprofile.Mapping
	executables        *lru.SyncedLRU[libpf.FileID, execInfo]
	processes          *lru.SyncedLRU[libpf.PID, processMetadata]
	totalSampleCount   int
	pidsWithNoMetadata libpf.Set[libpf.PID]
	timeline           bool
	samplingPeriod     int64
}

func newProfileBuilder(start, end time.Time, samplesPerSecond int, numSamples int, timeline bool,
	executables *lru.SyncedLRU[libpf.FileID, execInfo], processes *lru.SyncedLRU[libpf.PID, processMetadata]) *profileBuilder {
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

	return &profileBuilder{
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

func (b *profileBuilder) addEvents(events keyToEventMapping) {
	const unknownStr = "UNKNOWN"

	for traceKey, traceInfo := range events {
		sample := &pprofile.Sample{}

		// Walk every frame of the trace.
		for _, uniqueFrame := range traceInfo.Frames {
			frame := uniqueFrame.Value()
			loc := createPProfLocation(b.profile, uint64(frame.AddressOrLineno))

			switch frameKind := frame.Type; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				if tmpMapping, exists := b.fileIDtoMapping[frame.FileID]; exists {
					loc.Mapping = tmpMapping
				} else {
					executionInfo, exists := b.executables.GetAndRefresh(frame.FileID, executableCacheLifetime)

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = unknownStr
					var buildID = frame.FileID.StringNoQuotes()
					if exists {
						fileName = executionInfo.fileName
						buildID = getBuildID(executionInfo.gnuBuildID, executionInfo.goBuildID, buildID)
					}

					tmpMapping := createPprofMapping(b.profile, uint64(frame.AddressOrLineno),
						fileName, buildID)
					b.fileIDtoMapping[frame.FileID] = tmpMapping
					loc.Mapping = tmpMapping
				}
				line := pprofile.Line{Function: createPprofFunctionEntry(b.funcMap, b.profile, "",
					loc.Mapping.File)}
				loc.Line = append(loc.Line, line)
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as Line message:
				line := pprofile.Line{
					Line: int64(frame.SourceLine),
					Function: createPprofFunctionEntry(b.funcMap, b.profile,
						frame.FunctionName.String(), frame.SourceFile.String()),
				}

				loc.Line = append(loc.Line, line)
				// To be compliant with the protocol generate a dummy mapping entry.
				loc.Mapping = getDummyMapping(b.fileIDtoMapping, b.profile, frame.FileID)
			}
			sample.Location = append(sample.Location, loc)
		}

		processMeta, ok := b.processes.Get(traceKey.pid)
		if !ok {
			b.pidsWithNoMetadata[traceKey.pid] = libpf.Void{}
		}
		execPath := traceKey.executablePath
		baseExec := path.Base(execPath)

		if execPath != "" {
			loc := createPProfLocation(b.profile, 0)
			m := createPprofFunctionEntry(b.funcMap, b.profile, baseExec, execPath)
			loc.Line = append(loc.Line, pprofile.Line{Function: m})
			sample.Location = append(sample.Location, loc)
		}

		if !b.timeline {
			count := int64(len(traceInfo.Timestamps))
			labels := make(map[string][]string)
			addTraceLabels(labels, traceKey, processMeta.containerMetadata, baseExec, 0)
			sample.Value = append(sample.Value, count, count*b.samplingPeriod)
			sample.Label = labels
			b.profile.Sample = append(b.profile.Sample, sample)
		} else {
			sample.Value = append(sample.Value, 1, b.samplingPeriod)
			for _, ts := range traceInfo.Timestamps {
				sampleWithTimestamp := &pprofile.Sample{}
				*sampleWithTimestamp = *sample
				labels := make(map[string][]string)
				addTraceLabels(labels, traceKey, processMeta.containerMetadata, baseExec, ts)
				sampleWithTimestamp.Label = labels
				b.profile.Sample = append(b.profile.Sample, sampleWithTimestamp)
			}
		}
		b.totalSampleCount += len(traceInfo.Timestamps)
	}
}

func (b *profileBuilder) build() (*pprofile.Profile, profileStats) {
	profile := b.profile.Compact()
	stats := profileStats{
		totalSampleCount:  b.totalSampleCount,
		pidWithNoMetadata: len(b.pidsWithNoMetadata),
	}
	return profile, stats
}
