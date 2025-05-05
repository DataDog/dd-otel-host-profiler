// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// runLoop implements the run loop for all reporters
type runLoop struct {
	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void
}

func (rl *runLoop) Start(ctx context.Context, reportInterval time.Duration, run, purge func()) {
	go func() {
		tick := time.NewTicker(reportInterval)
		defer tick.Stop()
		purgeTick := time.NewTicker(5 * time.Minute)
		defer purgeTick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-rl.stopSignal:
				return
			case <-tick.C:
				tick.Reset(libpf.AddJitter(reportInterval, 0.05))
				run()
			case <-purgeTick.C:
				purge()
			}
		}
	}()
}

func (rl *runLoop) Stop() {
	close(rl.stopSignal)
}
