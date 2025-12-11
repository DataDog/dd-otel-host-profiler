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
	"strings"
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
	"github.com/DataDog/dd-otel-host-profiler/reporter/pprof"
	rsamples "github.com/DataDog/dd-otel-host-profiler/reporter/samples"
)

// Assert that we implement the full Reporter interface.
var _ reporter.Reporter = (*DatadogReporter)(nil)
var errUnknownOrigin = errors.New("unknown trace origin")

const (
	unknownServiceStr = "unknown-service"

	profilerName            = "dd-otel-host-profiler"
	pidCacheUpdateInterval  = 1 * time.Minute // pid cache items will be updated at most once per this interval
	pidCacheCleanupInterval = 5 * time.Minute // pid cache items for which metadata hasn't been updated in this interval will be removed

	profileUploadWorkerCount = 5
	profileUploadQueueSize   = 128
)

var ServiceNameEnvVars = []string{"DD_SERVICE", "OTEL_SERVICE_NAME"}

type uploadProfileData struct {
	start    time.Time
	end      time.Time
	profile  *pprofile.Profile
	entityID string
	tags     Tags
}

// DatadogReporter receives and transforms information to be OTLP/profiles compliant.
type DatadogReporter struct {
	config *Config

	// runLoop handles the run loop
	runLoop *runLoop

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long term storage information that might
	// be duplicated in other places but not accessible for DatadogReporter.

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[rsamples.TraceEventsTree]

	// processes stores the metadata associated to a PID.
	processes *lru.SyncedLRU[libpf.PID, rsamples.ProcessMetadata]

	symbolUploader *DatadogSymbolUploader

	containerMetadataProvider containermetadata.Provider

	// tags is the list of tags to be added to the profile.
	tags Tags

	// family is the family of the profiler.
	family string

	// profileSeq is the sequence number of the profile (ie. number of profiles uploaded until now).
	profileSeq uint64

	// processAlreadyExitedCount is the number of processes that have already exited when attempting to collect their metadata.
	processAlreadyExitedCount int

	// intervalStart is the timestamp of the start of the current interval.
	intervalStart time.Time

	// fileCounter is used to ensure unique local profile filenames
	fileCounter uint64

	profiles chan *uploadProfileData
}

func NewDatadog(ctx context.Context, cfg *Config, p containermetadata.Provider) (*DatadogReporter, error) {
	executables, err := lru.NewSynced[libpf.FileID, rsamples.ExecInfo](cfg.ExecutablesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	executables.SetLifetime(rsamples.ExecutableCacheLifetime)

	processes, err := lru.NewSynced[libpf.PID, rsamples.ProcessMetadata](cfg.ProcessesCacheElements, libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}
	processes.SetLifetime(pidCacheCleanupInterval)

	var symbolUploader *DatadogSymbolUploader
	if cfg.SymbolUploaderConfig.Enabled {
		symbolUploader, err = NewDatadogSymbolUploader(ctx, &cfg.SymbolUploaderConfig)
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
		containerMetadataProvider: p,
		traceEvents:               xsync.NewRWMutex(make(rsamples.TraceEventsTree)),
		processes:                 processes,
		symbolUploader:            symbolUploader,
		tags:                      createTags(cfg.Tags, runtimeTag, cfg.Version, cfg.EnableSplitByService, cfg.CollectContext && !cfg.UseRuntimeIDInServiceEntityKey),
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
	if !ok || time.Since(pMeta.UpdatedAt) > pidCacheUpdateInterval {
		// Retrieve process metadata if not yet available or if it's been too long since the last update.
		// Note that there are potential consistency issues between process metadata and trace events:
		// - Some parts of process metdata are used as keys in the trace events tree (service name, runtime ID, etc.) and might be stale.
		// - Some parts of process metadata are used when creating profiles (exec path) and the last update will be used for all trace events.
		pMeta = r.addProcessMetadata(trace, meta)
	}

	key := rsamples.TraceAndMetaKey{
		Hash: trace.Hash,
		Comm: meta.Comm.String(),
		Pid:  meta.PID,
		Tid:  meta.TID,
		CPU:  int64(meta.CPU),
	}

	eventsTree := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&eventsTree)

	serviceEntityKey := rsamples.ServiceEntity{
		Service:         pMeta.Service,
		EntityID:        pMeta.ContainerMetadata.EntityID,
		InferredService: pMeta.InferredService,
	}
	if r.config.UseRuntimeIDInServiceEntityKey && pMeta.TracingContext != nil {
		serviceEntityKey.RuntimeID = pMeta.TracingContext.ServiceInstanceID
		// We could also add all the process level context to the service entity key.
		// That could improve trace event / process context consistency.
	}

	perServiceEvents, exists := (*eventsTree)[serviceEntityKey]
	if !exists {
		perServiceEvents = make(map[libpf.Origin]rsamples.KeyToEventMapping)
		(*eventsTree)[serviceEntityKey] = perServiceEvents
	}

	perOriginEvents, exists := perServiceEvents[meta.Origin]
	if !exists {
		perOriginEvents = make(rsamples.KeyToEventMapping)
		perServiceEvents[meta.Origin] = perOriginEvents
	}

	if events, exists := perOriginEvents[key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.OffTimes = append(events.OffTimes, meta.OffTime)
		if r.config.CollectContext {
			events.CustomLabels = append(events.CustomLabels, trace.CustomLabels)
		}
		perOriginEvents[key] = events
		return nil
	}

	var customLabels []map[libpf.String]libpf.String
	if r.config.CollectContext {
		customLabels = []map[libpf.String]libpf.String{trace.CustomLabels}
	}

	perOriginEvents[key] = &rsamples.TraceEvents{
		TraceEvents: samples.TraceEvents{
			Frames:     trace.Frames,
			Timestamps: []uint64{uint64(meta.Timestamp)},
			OffTimes:   []int64{meta.OffTime},
			EnvVars:    meta.EnvVars,
		},
		CustomLabels: customLabels,
	}

	return nil
}

func (r *DatadogReporter) ReportExecutable(execMeta *reporter.ExecutableMetadata) {
	if r.symbolUploader != nil {
		r.symbolUploader.UploadSymbols(execMeta)
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

// Filename format examples:
// With service and entity: ./temp-my-service-abc123456789-20060102T150405Z-1.pprof
// With service only: ./temp-my-service-20060102T150405Z-1.pprof
// With entity only: ./temp-abc123456789-20060102T150405Z-1.pprof
// Fallback: ./temp-20060102T150405Z-1.pprof

// getServiceNameFromTags extracts the service name from the tags.
func getServiceNameFromTags(tags Tags) string {
	for _, tag := range tags {
		if tag.Key == "service" {
			return tag.Value
		}
	}
	return ""
}

// getEntityIDFromUploadData extracts a short entity ID for filename use.
func getEntityIDFromUploadData(entityID string) string {
	if entityID == "" {
		return ""
	}
	if len(entityID) > 15 { // Allow for "ci-" prefix (3 chars) + 12 chars = 15
		return entityID[:15]
	}
	return entityID
}

// sanitizeFilename removes or replaces characters that are not safe for filenames.
func sanitizeFilename(name string) string {
	return strings.Map(func(r rune) rune {
		// Keep alphanumeric characters, dashes, underscores, and dots
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		// in theory we only need to replace / and '\0', but this makes it slightly easier to read
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ':
			return '_'
		default:
			// Remove any other non-safe characters (e.g., unicode)
			return -1
		}
	}, name)
}

// generateProfileFilename creates a unique filename for a profile.
func (r *DatadogReporter) generateProfileFilename(data *uploadProfileData) string {
	serviceName := getServiceNameFromTags(data.tags)
	entityID := getEntityIDFromUploadData(data.entityID)

	// Increment counter for uniqueness
	r.fileCounter++

	// Build filename components
	var components []string
	components = append(components, r.config.PprofPrefix)

	if serviceName != "" {
		components = append(components, sanitizeFilename(serviceName))
	}

	if entityID != "" {
		components = append(components, sanitizeFilename(entityID))
	}

	// Add timestamp and counter for uniqueness
	components = append(components, data.end.Format("20060102T150405Z"), strconv.FormatUint(r.fileCounter, 10))

	return strings.Join(components, "-") + ".pprof"
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
		profileName := r.generateProfileFilename(data)
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

func (r *DatadogReporter) getProcessLevelContext(events rsamples.KeyToEventMapping) *rsamples.ProcessContext {
	// Service entity key only contains the runtime ID,
	// but to get the full process context we need to look up the process metadata.
	// We make the assumption that if several processes share the same runtime ID,
	// then they have the same process context.
	// To lookup the process metadata we use the first process in the events.

	// This loop is expected to run only once since all keys in the events map have the same runtime ID
	// and therefore should have a PID with a process context.
	for key := range events {
		pMeta, ok := r.processes.Get(key.Pid)
		if ok {
			return pMeta.TracingContext
		}
	}
	return nil
}

// getPprofProfile returns a pprof profile containing all collected samples up to this moment.
func (r *DatadogReporter) getPprofProfile() {
	intervalEnd := time.Now()
	intervalStart := r.intervalStart
	r.intervalStart = intervalEnd
	profileSeq := r.profileSeq
	r.profileSeq++
	r.fileCounter = 0 // reset file counter for each export cycle

	processAlreadyExitedCount := r.processAlreadyExitedCount
	r.processAlreadyExitedCount = 0

	events := r.traceEvents.WLock()
	reportedEvents := *events
	newEvents := make(rsamples.TraceEventsTree)
	*events = newEvents
	r.traceEvents.WUnlock(&events)

	if !r.config.EnableSplitByService {
		profileBuilder := pprof.NewProfileBuilder(&pprof.Config{
			Start:                       intervalStart,
			End:                         intervalEnd,
			SamplesPerSecond:            r.config.SamplesPerSecond,
			NumSamples:                  len(reportedEvents),
			Timeline:                    r.config.Timeline,
			ProcessLevelContextAsLabels: !r.config.UseRuntimeIDInServiceEntityKey,
			Processes:                   r.processes,
		})

		for _, events := range reportedEvents {
			profileBuilder.AddEvents(events[support.TraceOriginSampling])
		}
		profile, stats := profileBuilder.Build()

		serviceEntity := rsamples.ServiceEntity{
			Service: r.config.HostServiceName,
		}
		tags := createTagsForProfile(r.tags, profileSeq, serviceEntity)
		r.profiles <- &uploadProfileData{
			profile: profile,
			start:   intervalStart,
			end:     intervalEnd,
			tags:    tags,
		}
		log.Infof("Tags: %v", tags)
		log.Infof("Reporting single profile #%d from %v to %v: %d samples, %d PIDs with no process metadata",
			profileSeq, intervalStart.Format(time.RFC3339), intervalEnd.Format(time.RFC3339), stats.TotalSampleCount, processAlreadyExitedCount)
		return
	}

	totalSampleCount := 0
	for s, perServiceEvents := range reportedEvents {
		profileBuilder := pprof.NewProfileBuilder(&pprof.Config{
			Start:                       intervalStart,
			End:                         intervalEnd,
			SamplesPerSecond:            r.config.SamplesPerSecond,
			NumSamples:                  len(reportedEvents),
			Timeline:                    r.config.Timeline,
			ProcessLevelContextAsLabels: !r.config.UseRuntimeIDInServiceEntityKey,
			Processes:                   r.processes,
		})

		events := perServiceEvents[support.TraceOriginSampling]
		profileBuilder.AddEvents(events)
		profile, stats := profileBuilder.Build()
		totalSampleCount += stats.TotalSampleCount

		tags := createTagsForProfile(r.tags, profileSeq, s)
		if s.RuntimeID != "" {
			processContext := r.getProcessLevelContext(events)
			if processContext != nil {
				tags = addProcessLevelContextTags(tags, processContext)
			}
		}

		r.profiles <- &uploadProfileData{
			profile:  profile,
			start:    intervalStart,
			end:      intervalEnd,
			entityID: s.EntityID,
			tags:     tags,
		}
		log.Debugf("Reporting profile for service %s: %d samples, tags: %v", s.Service, stats.TotalSampleCount, tags)
	}
	log.Infof("Reporting %d profiles #%d from %v to %v: %d samples, %d PIDs with no process metadata",
		len(reportedEvents), profileSeq, intervalStart.Format(time.RFC3339), intervalEnd.Format(time.RFC3339), totalSampleCount, processAlreadyExitedCount)
}

func createTags(userTags Tags, runtimeTag, version string, splitByServiceEnabled, processLevelContextAsLabels bool) Tags {
	tags := append(Tags{}, userTags...)

	customContextTagKey := "ddprof.custom_ctx"
	tags = append(tags, MakeTag(customContextTagKey, pprof.CPUIDLabel))
	if !splitByServiceEnabled {
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
		MakeTag("cpu_arch", runtime.GOARCH),
	)

	if processLevelContextAsLabels {
		// If process level context is emitted as sample labels, make these labels available as custom context.
		tags = append(tags,
			MakeTag(customContextTagKey, "env"),
			MakeTag(customContextTagKey, "runtime-id"),
			MakeTag(customContextTagKey, "service_name"),
			MakeTag(customContextTagKey, "service_version"),
			MakeTag(customContextTagKey, "telemetry_sdk_language"),
			MakeTag(customContextTagKey, "telemetry_sdk_name"),
			MakeTag(customContextTagKey, "telemetry_sdk_version"),
		)
	}

	return tags
}

func createTagsForProfile(tags Tags, profileSeq uint64, serviceEntity rsamples.ServiceEntity) Tags {
	newTags := append(Tags{}, tags...)
	newTags = append(newTags,
		MakeTag("profile_seq", strconv.FormatUint(profileSeq, 10)),
		MakeTag("service", serviceEntity.Service))
	inferredServiceTag := "no"
	if serviceEntity.InferredService {
		inferredServiceTag = "yes"
	}
	newTags = append(newTags, MakeTag("service_inferred", inferredServiceTag))
	return newTags
}

func addProcessLevelContextTags(tags Tags, processContext *rsamples.ProcessContext) Tags {
	tags = append(tags,
		MakeTag("env", processContext.DeploymentEnvironmentName),
		MakeTag("runtime-id", processContext.ServiceInstanceID),
		MakeTag("service_name", processContext.ServiceName),
		MakeTag("service_version", processContext.ServiceVersion),
		MakeTag("host_name", processContext.HostName),
		MakeTag("telemetry_sdk_language", processContext.TelemetrySdkLanguage),
		MakeTag("telemetry_sdk_name", processContext.TelemetrySdkName),
		MakeTag("telemetry_sdk_version", processContext.TelemetrySdkVersion),
	)
	return tags
}

func (r *DatadogReporter) addProcessMetadata(trace *libpf.Trace, meta *samples.TraceEventMeta) rsamples.ProcessMetadata {
	pid := meta.PID
	execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// Process might have exited since the trace was collected or process is a kernel thread.
		log.Debugf("Failed to get process metadata for PID %d: %v", pid, err)
		execPath = meta.ExecutablePath.String()
	}
	// Trim the "(deleted)" suffix if it exists.
	// This can happen when the executable has been deleted or replaced while the process is running.
	execPath = strings.TrimSuffix(execPath, " (deleted)")

	var processName string
	if name, err2 := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err2 == nil {
		processName = string(name)
	} else {
		r.processAlreadyExitedCount++
		processName = meta.ProcessName.String()
	}

	var service string
	for _, envVarName := range ServiceNameEnvVars {
		if s, ok := meta.EnvVars[libpf.Intern(envVarName)]; ok {
			service = s.String()
			break
		}
	}

	// If DD_SERVICE is not set and the executable path is different from the one in the trace
	// (meaning the process has probably exec'd into another binary)
	// then attempt to retrieve again DD_SERVICE.
	// This can occur when a container is started, during startup the process is runc
	// (without the final container environment) that then execs into the final binary
	// with the container environment.
	if service == "" && meta.ExecutablePath.String() != execPath {
		service = getServiceName(pid)
	}

	var tracingCtx *rsamples.ProcessContext
	if r.config.CollectContext {
		tracingCtx, err = ReadProcessLevelContext(pid, r.config.KernelSupportsNamedAnonymousMappings)
		if err == nil {
			// TODO: switch to debug log once context collection is enabled by default
			log.Infof("read process context for pid %d: %+v", pid, tracingCtx)
			if tracingCtx.ServiceName != "" {
				service = tracingCtx.ServiceName
			}
		}
	}

	inferredService := false
	switch {
	case service != "":
		// containerd shim injects an OTEL_SERVICE_NAME environment variable that contains a hash of the container ID
		// see https://github.com/containerd/containerd/blob/1ce8e1ca0e43ae5942c6b60906b653107c442ce9/cmd/containerd-shim-runc-v2/manager/manager_linux.go#L106
		// to avoid polluting the interface with multiple service names, we replace it with "containerd-shim"
		if strings.HasPrefix(service, "containerd-shim-") {
			service = "containerd-shim"
		}
	case execPath != "":
		service = path.Base(execPath)
		inferredService = true
	case rsamples.IsKernel(trace.Frames):
		service = "system"
	case processName != "":
		service = processName
		inferredService = true
	case meta.Comm != libpf.NullString:
		service = meta.Comm.String()
		inferredService = true
	default:
		service = unknownServiceStr
		inferredService = true
	}

	var containerMetadata containermetadata.ContainerMetadata
	if meta.ContainerID != libpf.NullString && r.config.EnableSplitByService {
		// Use containerID when found by the eBPF profiler and not other container metadata is needed
		// (ie. split by service is enabled).
		// eBPF profiler only supports cgroup v2 and even with cgroup v2, depending on Kubernetes settings,
		// containerID might not be available in /proc/<pid>/cgroup.
		containerMetadata = containermetadata.ContainerMetadata{
			EntityID: "ci-" + meta.ContainerID.String(),
		}
	} else {
		containerMetadata, err = r.containerMetadataProvider.GetContainerMetadata(pid)
		if err != nil {
			log.Debugf("Failed to get container metadata for PID %d: %v", pid, err)
			// Even upon failure, we might still have managed to get the containerID
		}
	}

	pMeta := rsamples.ProcessMetadata{
		UpdatedAt:         time.Now(),
		ExecutablePath:    strings.TrimSpace(execPath),
		ProcessName:       strings.TrimSpace(processName),
		ContainerMetadata: containerMetadata,
		Service:           strings.TrimSpace(service),
		InferredService:   inferredService,
		TracingContext:    tracingCtx,
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
	for envVar := range bytes.SplitSeq(envData, []byte{0}) {
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
