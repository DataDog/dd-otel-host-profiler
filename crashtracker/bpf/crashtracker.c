// Minimal eBPF program skeleton for crash tracking.
// This file is compiled by bpf2go to generate Go bindings.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_STACK_DEPTH 128
#define TASK_COMM_LEN   16

#define CRASH_EVENT_SIGNAL    1
#define CRASH_EVENT_OOM       2
#define CRASH_EVENT_CONFIRMED 3

struct crash_event {
	__u8  event_type;
	__u8  _pad[3];

	// Signal context
	__u32 sig;
	__u32 sig_code;
	__u64 sig_addr;

	// Process identity
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	char  comm[TASK_COMM_LEN];

	// Timing
	__u64 ktime_ns;
	__u64 boottime_ns;

	// Registers (x86_64 — extended at runtime via core handler)
	__u64 ip;
	__u64 sp;

	// Stack traces
	__u32 user_stack_len;
	__u32 kern_stack_len;
	__u64 user_stack[MAX_STACK_DEPTH];
	__u64 kern_stack[MAX_STACK_DEPTH];

	// Container context
	__u64 cgroup_id;
	__u32 pid_ns_id;
};

// Ring buffer for delivering crash events to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256 KB
} crash_events SEC(".maps");

// Track unconfirmed crashes awaiting process exit confirmation.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   // pid
	__type(value, __u64); // timestamp
} pending_crashes SEC(".maps");

// Rate limiting: track last crash timestamp per PID.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   // pid
	__type(value, __u64); // last crash ktime_ns
} rate_limit SEC(".maps");

#define RATE_LIMIT_WINDOW_NS 1000000000ULL // 1 second

static __always_inline int is_fatal_signal(int sig) {
	return sig == 4  /* SIGILL  */ ||
	       sig == 5  /* SIGTRAP */ ||
	       sig == 6  /* SIGABRT */ ||
	       sig == 7  /* SIGBUS  */ ||
	       sig == 8  /* SIGFPE  */ ||
	       sig == 11 /* SIGSEGV */;
}

static __always_inline int rate_limited(__u32 pid, __u64 now) {
	__u64 *last = bpf_map_lookup_elem(&rate_limit, &pid);
	if (last && (now - *last) < RATE_LIMIT_WINDOW_NS)
		return 1;
	bpf_map_update_elem(&rate_limit, &pid, &now, BPF_ANY);
	return 0;
}

SEC("tracepoint/signal/signal_deliver")
int tracepoint__signal__signal_deliver(struct trace_event_raw_signal_deliver *ctx) {
	int sig = ctx->sig;

	if (!is_fatal_signal(sig))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 now = bpf_ktime_get_ns();

	if (rate_limited(pid, now))
		return 0;

	struct crash_event *event = bpf_ringbuf_reserve(&crash_events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->event_type = CRASH_EVENT_SIGNAL;
	event->sig = sig;
	event->sig_code = ctx->code;
	event->sig_addr = ctx->sa_handler; // si_addr passed via tracepoint varies by kernel

	event->pid = pid;
	event->tid = tid;

	__u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;
	event->gid = uid_gid >> 32;

	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->ktime_ns = now;
	event->boottime_ns = bpf_ktime_get_boot_ns();

	// Capture user and kernel stacks
	int ulen = bpf_get_stack(ctx, event->user_stack, sizeof(event->user_stack), BPF_F_USER_STACK);
	event->user_stack_len = ulen > 0 ? ulen / 8 : 0;

	int klen = bpf_get_stack(ctx, event->kern_stack, sizeof(event->kern_stack), 0);
	event->kern_stack_len = klen > 0 ? klen / 8 : 0;

	event->cgroup_id = bpf_get_current_cgroup_id();

	bpf_ringbuf_submit(event, 0);

	// Mark as pending confirmation
	bpf_map_update_elem(&pending_crashes, &pid, &now, BPF_ANY);

	return 0;
}

SEC("tracepoint/oom/mark_victim")
int tracepoint__oom__mark_victim(struct trace_event_raw_mark_victim *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 now = bpf_ktime_get_ns();

	struct crash_event *event = bpf_ringbuf_reserve(&crash_events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->event_type = CRASH_EVENT_OOM;
	event->sig = 9; // SIGKILL
	event->sig_code = 0;
	event->sig_addr = 0;

	event->pid = pid;
	event->tid = tid;

	__u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;
	event->gid = uid_gid >> 32;

	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->ktime_ns = now;
	event->boottime_ns = bpf_ktime_get_boot_ns();

	int ulen = bpf_get_stack(ctx, event->user_stack, sizeof(event->user_stack), BPF_F_USER_STACK);
	event->user_stack_len = ulen > 0 ? ulen / 8 : 0;

	int klen = bpf_get_stack(ctx, event->kern_stack, sizeof(event->kern_stack), 0);
	event->kern_stack_len = klen > 0 ? klen / 8 : 0;

	event->cgroup_id = bpf_get_current_cgroup_id();

	bpf_ringbuf_submit(event, 0);

	// OOM kills are always fatal — no confirmation needed
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	__u64 *pending_ts = bpf_map_lookup_elem(&pending_crashes, &pid);
	if (!pending_ts)
		return 0;

	// Emit confirmation event
	struct crash_event *event = bpf_ringbuf_reserve(&crash_events, sizeof(*event), 0);
	if (!event) {
		bpf_map_delete_elem(&pending_crashes, &pid);
		return 0;
	}

	event->event_type = CRASH_EVENT_CONFIRMED;
	event->pid = pid;
	event->ktime_ns = bpf_ktime_get_ns();

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pending_crashes, &pid);

	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Force BTF emission of crash_event so bpf2go can generate Go types. */
struct crash_event *__unused_crash_event __attribute__((unused));
