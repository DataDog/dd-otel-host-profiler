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
	"log/slog"
	"os"
	"os/signal"

	ebpfLog "go.opentelemetry.io/ebpf-profiler/log"
	"golang.org/x/sys/unix"

	"github.com/DataDog/dd-otel-host-profiler/config"
	"github.com/DataDog/dd-otel-host-profiler/runner"
)

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() runner.ExitCode {
	args, err := config.ParseArgs()
	fmt.Println("hello")
	if err != nil {
		return runner.ParseError("Failure to parse arguments", "error", err)
	}

	if args == nil {
		return runner.ExitSuccess
	}

	if args.Copyright {
		fmt.Print(config.Copyright)
		return runner.ExitSuccess
	}

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	ebpfLog.SetLogger(*slog.Default())
	if args.VerboseMode {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		// Dump the arguments in debug mode.
		args.Dump()
	}

	return runner.Run(mainCtx, &args.Config)
}
