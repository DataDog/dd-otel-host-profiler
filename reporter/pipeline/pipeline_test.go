// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

func TestPipeline(t *testing.T) {
	t.Run("EmptyPipeline", func(_ *testing.T) {
		input := make(chan int)
		p := NewPipeline(input)
		p.Start(context.Background())
		p.Stop()
	})

	t.Run("PipelineWithOneSink", func(t *testing.T) {
		input := make(chan int)
		output := make(chan int)
		p := NewPipeline(input, NewSinkStage(input,
			func(_ context.Context, x int) {
				output <- x * 2
			}))
		p.Start(context.Background())
		input <- 1
		require.Equal(t, 2, <-output)
		p.Stop()
	})

	t.Run("PipelineWithMultipleStages", func(t *testing.T) {
		input := make(chan int)
		output := make(chan int)
		stage1 := NewStage(input,
			func(_ context.Context, x int, outputChan chan<- []int) {
				outputChan <- []int{x * 2, x * 3}
			})
		stage2 := NewSinkStage(stage1.GetOutputChannel(),
			func(_ context.Context, x []int) {
				var sum int
				for _, v := range x {
					sum += v
				}
				output <- sum
			})
		p := NewPipeline(input, stage1, stage2)
		p.Start(context.Background())
		go func() {
			input <- 1
			input <- 2
		}()
		require.Equal(t, 5, <-output)
		require.Equal(t, 10, <-output)
		p.Stop()
	})

	t.Run("GracefulShutdown", func(t *testing.T) {
		input := make(chan int, 1000)
		for i := range 1000 {
			input <- i
		}
		var output []int
		var mut sync.Mutex
		stage1 := NewStage(input,
			func(_ context.Context, x int, outputChan chan<- int) {
				outputChan <- x * 2
			}, WithConcurrency(10))
		stage2 := NewStage(stage1.GetOutputChannel(),
			func(_ context.Context, x int, outputChan chan<- int) {
				outputChan <- x + 1
			}, WithConcurrency(10))
		stage3 := NewSinkStage(stage2.GetOutputChannel(),
			func(_ context.Context, x int) {
				mut.Lock()
				output = append(output, x)
				mut.Unlock()
			}, WithConcurrency(10))

		p := NewPipeline(input, stage1, stage2, stage3)
		p.Start(context.Background())
		p.Stop()
		require.Len(t, output, 1000)
	})

	t.Run("PipelineWithBatchingStageNoInterval", func(t *testing.T) {
		input := make(chan int, 1000)
		for i := range 999 {
			input <- i
		}
		var output [][]int
		stage1 := NewBatchingStage[int](input, 0, 10)
		stage2 := NewSinkStage(stage1.GetOutputChannel(),
			func(_ context.Context, x []int) {
				output = append(output, x)
			})
		p := NewPipeline(input, stage1, stage2)
		p.Start(context.Background())
		p.Stop()
		require.Len(t, output, 100)
		require.Len(t, output[99], 9)
	})

	t.Run("PipelineWithBatchingStageWithInterval", func(t *testing.T) {
		input := make(chan int, 1000)
		for i := range 9 {
			input <- i
		}
		clock := clockwork.NewFakeClock()
		stage1 := NewBatchingStageWithClock(input, 1*time.Second, 10, clock,
			WithOutputChanSize(1))
		p := NewPipeline(input, stage1)
		output := stage1.GetOutputChannel()
		p.Start(context.Background())
		require.NoError(t, clock.BlockUntilContext(context.Background(), 1))
		clock.Advance(1 * time.Second)
		require.Len(t, <-output, 9)
		clock.Advance(999 * time.Millisecond)
		for i := range 15 {
			input <- i
		}
		require.Len(t, <-output, 10)
		clock.Advance(1 * time.Millisecond)
		require.NoError(t, clock.BlockUntilContext(context.Background(), 1))
		require.Empty(t, output)
		clock.Advance(999 * time.Millisecond)
		require.NoError(t, clock.BlockUntilContext(context.Background(), 1))
		require.Len(t, <-output, 5)
		for i := range 5 {
			input <- i
		}
		p.Stop()
		require.Len(t, <-output, 5)
	})
}
