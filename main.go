/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/DataDog/dd-otel-host-profiler/hostprofilerrunner"
)

// Short copyright / license text for eBPF code
const copyright = `Copyright 2024 Datadog, Inc.

For the eBPF code loaded by Universal Profiling Agent into the kernel,
the following license applies (GPLv2 only). You can obtain a copy of the GPLv2 code at:
https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/support/ebpf

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 only,
as published by the Free Software Foundation;

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details:

https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
`

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() hostprofilerrunner.ExitCode {
	args, err := parseArgs()
	if err != nil {
		return hostprofilerrunner.ParseError("Failure to parse arguments: %v", err)
	}

	if args == nil {
		return hostprofilerrunner.ExitSuccess
	}

	if args.copyright {
		fmt.Print(copyright)
		return hostprofilerrunner.ExitSuccess
	}

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if args.verboseMode {
		log.SetLevel(log.DebugLevel)
		// Dump the arguments in debug mode.
		args.dump()
	}

	return hostprofilerrunner.RunHostProfiler(mainCtx, &args.FullHostProfilerSettings)
}
