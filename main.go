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

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() hostprofilerrunner.ExitCode {
	args, err := hostprofilerrunner.ParseArgs()
	if err != nil {
		return hostprofilerrunner.ParseError("Failure to parse arguments: %v", err)
	}

	if args == nil {
		return hostprofilerrunner.ExitSuccess
	}

	if args.Copyright {
		fmt.Print(hostprofilerrunner.Copyright)
		return hostprofilerrunner.ExitSuccess
	}

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if args.VerboseMode {
		log.SetLevel(log.DebugLevel)
		// Dump the arguments in debug mode.
		args.Dump()
	}

	return hostprofilerrunner.RunHostProfiler(mainCtx, &args.FullHostProfilerSettings)
}
