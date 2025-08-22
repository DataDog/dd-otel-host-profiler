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

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, rsamples.ExecInfo]

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

	profiles chan *uploadProfileData
}

func NewDatadog(cfg *Config, p containermetadata.Provider) (*DatadogReporter, error) {
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
		traceEvents:               xsync.NewRWMutex(make(rsamples.TraceEventsTree)),
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
	if !ok || time.Since(pMeta.UpdatedAt) > pidCacheUpdateInterval {
		pMeta = r.addProcessMetadata(trace, meta)
	}

	key := rsamples.TraceAndMetaKey{
		Hash: trace.Hash,
		Comm: meta.Comm,
		Pid:  meta.PID,
		Tid:  meta.TID,
	}

	eventsTree := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&eventsTree)

	serviceEntityKey := rsamples.ServiceEntity{
		Service:         pMeta.Service,
		EntityID:        pMeta.ContainerMetadata.EntityID,
		InferredService: pMeta.InferredService,
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
	_, known := r.executables.GetAndRefresh(fileID, rsamples.ExecutableCacheLifetime)
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *DatadogReporter) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {
	r.executables.Add(args.FileID, rsamples.ExecInfo{
		FileName:   path.Base(args.FileName),
		GnuBuildID: args.GnuBuildID,
		GoBuildID:  args.GoBuildID,
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

	processAlreadyExitedCount := r.processAlreadyExitedCount
	r.processAlreadyExitedCount = 0

	events := r.traceEvents.WLock()
	reportedEvents := *events
	newEvents := make(rsamples.TraceEventsTree)
	*events = newEvents
	r.traceEvents.WUnlock(&events)

	if !r.config.EnableSplitByService {
		profileBuilder := pprof.NewProfileBuilder(intervalStart, intervalEnd, r.config.SamplesPerSecond, len(reportedEvents), r.config.Timeline, r.executables, r.processes)

		for _, events := range reportedEvents {
			profileBuilder.AddEvents(events[support.TraceOriginSampling])
		}
		profile, stats := profileBuilder.Build()

		tags := createTagsForProfile(r.tags, profileSeq, r.config.HostServiceName, false)
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
		profileBuilder := pprof.NewProfileBuilder(intervalStart, intervalEnd, r.config.SamplesPerSecond, len(reportedEvents), r.config.Timeline, r.executables, r.processes)

		profileBuilder.AddEvents(perServiceEvents[support.TraceOriginSampling])
		profile, stats := profileBuilder.Build()
		totalSampleCount += stats.TotalSampleCount
		tags := createTagsForProfile(r.tags, profileSeq, s.Service, s.InferredService)
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

func createTags(userTags Tags, runtimeTag, version string, splitByServiceEnabled bool) Tags {
	tags := append(Tags{}, userTags...)

	customContextTagKey := "ddprof.custom_ctx"
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
		MakeTag(customContextTagKey, "env"),
		MakeTag(customContextTagKey, "runtime_id"),
	)

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

func (r *DatadogReporter) addProcessMetadata(trace *libpf.Trace, meta *samples.TraceEventMeta) rsamples.ProcessMetadata {
	pid := meta.PID
	execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// Process might have exited since the trace was collected or process is a kernel thread.
		log.Debugf("Failed to get process metadata for PID %d: %v", pid, err)
		execPath = meta.ExecutablePath
	}
	// Trim the "(deleted)" suffix if it exists.
	// This can happen when the executable has been deleted or replaced while the process is running.
	execPath = strings.TrimSuffix(execPath, " (deleted)")

	var processName string
	if name, err2 := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err2 == nil {
		processName = string(name)
	} else {
		r.processAlreadyExitedCount++
		processName = meta.ProcessName
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

	var deploymentEnvironmentName string
	var serviceInstanceID string
	if tracerCtx, err2 := ReadProcessLevelContext(pid); err2 == nil {
		if tracerCtx.ServiceName != "" {
			service = tracerCtx.ServiceName
		}
		deploymentEnvironmentName = tracerCtx.DeploymentEnvironmentName
		serviceInstanceID = tracerCtx.ServiceInstanceID
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
	case meta.Comm != "":
		service = meta.Comm
		inferredService = true
	default:
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

	pMeta := rsamples.ProcessMetadata{
		UpdatedAt:                 time.Now(),
		ExecutablePath:            strings.TrimSpace(execPath),
		ProcessName:               strings.TrimSpace(processName),
		ContainerMetadata:         containerMetadata,
		Service:                   strings.TrimSpace(service),
		InferredService:           inferredService,
		DeploymentEnvironmentName: deploymentEnvironmentName,
		ServiceInstanceID:         serviceInstanceID,
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
