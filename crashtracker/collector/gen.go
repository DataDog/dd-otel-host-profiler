package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type crash_event crashtracker ../bpf/crashtracker.c -- -I../bpf/headers -I/usr/include
