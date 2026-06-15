/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Minimal vmlinux.h for the eBPF crashtracker.
 *
 * Contains only the kernel types referenced by crashtracker.c.
 * With CO-RE (Compile Once - Run Everywhere), BPF programs are compiled
 * against these type definitions but field accesses are relocated at load
 * time to match the target kernel's actual layout via BTF.
 *
 * To regenerate a full vmlinux.h (not needed for this program):
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short int __s16;
typedef int __s32;
typedef long long __s64;

typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;

typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

typedef _Bool bool;
#define true 1
#define false 0

/* Network byte-order types (needed by bpf_helper_defs.h) */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u32 __wsum;

/* BPF map types */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_RINGBUF = 27,
};

/* BPF map update flags */
enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* BPF stack flags */
#define BPF_F_USER_STACK (1ULL << 8)

/* Tracepoint base entry */
struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

/* signal:signal_deliver tracepoint context */
struct trace_event_raw_signal_deliver {
	struct trace_entry ent;
	int sig;
	int errno;
	int code;
	long unsigned int sa_handler;
	long unsigned int sa_flags;
	char __data[0];
};

/* oom:mark_victim tracepoint context */
struct trace_event_raw_mark_victim {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

/* sched:sched_process_exit tracepoint context */
struct trace_event_raw_sched_process_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
