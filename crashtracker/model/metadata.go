package model

// OsInfo describes the operating system and architecture.
type OsInfo struct {
	Architecture string `json:"architecture"`
	Bitness      string `json:"bitness"`
	OsType       string `json:"os_type"`
	Version      string `json:"version"`
}

// ProcInfo contains process-level information.
type ProcInfo struct {
	PID uint32 `json:"pid"`
	TID uint32 `json:"tid,omitempty"`
}

// Ucontext contains CPU register state captured at crash time.
type Ucontext struct {
	Arch      string            `json:"arch,omitempty"`
	Registers map[string]string `json:"registers"`
	Raw       string            `json:"raw,omitempty"`
}

// Metadata describes the crash collector and its context.
type Metadata struct {
	LibraryName    string   `json:"library_name"`
	LibraryVersion string   `json:"library_version"`
	Family         string   `json:"family"`
	Tags           []string `json:"tags,omitempty"`
}

// SpanRef references an active span or trace at crash time.
type SpanRef struct {
	ID         string `json:"id"`
	ThreadName string `json:"thread_name,omitempty"`
}

// Experimental holds unstable/extension data that consumers should pass along unmodified.
type Experimental struct {
	AdditionalTags []string     `json:"additional_tags,omitempty"`
	KernelStack    *StackTrace  `json:"kernel_stack,omitempty"`
	RuntimeStack   *StackTrace  `json:"runtime_stack,omitempty"`
	ContainerInfo  *ContainerInfo `json:"container_info,omitempty"`
	MemoryInfo     *MemoryInfo  `json:"memory_info,omitempty"`
	ProcessInfo    *ProcessInfoExtended `json:"process_info_extended,omitempty"`
	CollectionMeta *CollectionMetadata `json:"collection_metadata,omitempty"`
}

// ContainerInfo holds container and Kubernetes metadata.
type ContainerInfo struct {
	ContainerID   string            `json:"container_id,omitempty"`
	PodName       string            `json:"pod_name,omitempty"`
	ContainerName string            `json:"container_name,omitempty"`
	Namespace     string            `json:"namespace,omitempty"`
	NodeName      string            `json:"node_name,omitempty"`
	Image         string            `json:"image,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// MemoryInfo holds memory-related metrics from /proc and cgroup.
type MemoryInfo struct {
	VmPeakKB             uint64 `json:"vm_peak_kb,omitempty"`
	VmSizeKB             uint64 `json:"vm_size_kb,omitempty"`
	VmRSSKB              uint64 `json:"vm_rss_kb,omitempty"`
	VmSwapKB             uint64 `json:"vm_swap_kb,omitempty"`
	VmDataKB             uint64 `json:"vm_data_kb,omitempty"`
	VmStkKB              uint64 `json:"vm_stk_kb,omitempty"`
	Threads              uint32 `json:"threads,omitempty"`
	FDCount              uint32 `json:"fd_count,omitempty"`
	OOMScore             int32  `json:"oom_score,omitempty"`
	CgroupMemoryLimitBytes uint64 `json:"cgroup_memory_limit_bytes,omitempty"`
	CgroupMemoryUsageBytes uint64 `json:"cgroup_memory_usage_bytes,omitempty"`
}

// ProcessInfoExtended holds additional process metadata beyond ProcInfo.
type ProcessInfoExtended struct {
	ExePath     string `json:"exe_path,omitempty"`
	Cmdline     string `json:"cmdline,omitempty"`
	UID         uint32 `json:"uid,omitempty"`
	GID         uint32 `json:"gid,omitempty"`
	StartTimeNs uint64 `json:"start_time_ns,omitempty"`
	UptimeNs    uint64 `json:"uptime_ns,omitempty"`
	PPID        uint32 `json:"ppid,omitempty"`
}

// CollectionMetadata describes how the crash data was collected.
type CollectionMetadata struct {
	Quality              string `json:"quality,omitempty"`
	BPFStackCaptured     bool   `json:"bpf_stack_captured"`
	CoreHandlerUsed      bool   `json:"core_handler_used"`
	CachedMappingsUsed   bool   `json:"cached_mappings_used"`
	CrashConfirmed       bool   `json:"crash_confirmed"`
	CollectionDurationMs uint32 `json:"collection_duration_ms,omitempty"`
}
