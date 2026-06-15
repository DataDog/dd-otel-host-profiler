package main

import (
	"fmt"
	"os"
	"strconv"
)

// core-handler is invoked by the kernel via /proc/sys/kernel/core_pattern:
//   |/usr/lib/crashtracker/core-handler %p %s %t %e %P
//
// Arguments:
//   %p = PID of crashing process (in initial PID namespace)
//   %s = signal number
//   %t = time of crash (seconds since epoch)
//   %e = executable filename
//   %P = PID in the PID namespace of the crashing process
//
// The core ELF file is delivered on stdin.
// The handler connects to the daemon via unix socket, sends enrichment data,
// and exits. The process remains frozen until this handler exits.

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: core-handler <pid> <signal> <time> <exe> [ns_pid]\n")
		return 1
	}

	pid, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pid: %s\n", os.Args[1])
		return 1
	}

	sig, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid signal: %s\n", os.Args[2])
		return 1
	}

	_ = os.Args[3] // time (seconds since epoch)
	exe := os.Args[4]

	fmt.Fprintf(os.Stderr, "core-handler: pid=%d sig=%d exe=%s\n", pid, sig, exe)

	// TODO(M3): Implement core handler logic:
	// 1. Connect to daemon unix socket at /run/crashtracker.sock
	// 2. Send CrashStartMsg
	// 3. Read /proc/<pid>/maps, /proc/<pid>/status, etc.
	// 4. Parse core ELF from stdin (NT_PRSTATUS for registers)
	// 5. Collect all thread states from /proc/<pid>/task/*/
	// 6. Send enrichment data to daemon
	// 7. Exit (kernel reaps the process)
	_ = pid
	_ = sig

	return 0
}
