// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
)

type Stage interface {
	Start(ctx context.Context)
	Stop()
	Connect(next Stage) error
	SetConcurrency(concurrency int)
	SetOutputChanSize(size int)
}

type Consumer[In any] interface {
	SetInputChannel(chan In)
}

type baseWorker[In any, Out any] struct {
	wg          sync.WaitGroup
	inputChan   <-chan In
	outputChan  chan Out
	concurrency int
}

func (w *baseWorker[In, Out]) Stop() {
	if w.outputChan != nil {
		defer close(w.outputChan)
	}
	w.wg.Wait()
}

func (w *baseWorker[In, Out]) SetInputChannel(inputChan chan In) {
	w.inputChan = inputChan
}

func (w *baseWorker[In, Out]) SetConcurrency(concurrency int) {
	w.concurrency = concurrency
}

func (w *baseWorker[In, Out]) SetOutputChanSize(size int) {
	w.outputChan = make(chan Out, size)
}

func (w *baseWorker[In, Out]) Connect(next Stage) error {
	if w.outputChan == nil {
		return errors.New("cannot connect sink stage")
	}
	w2, ok := next.(Consumer[Out])
	if !ok {
		return fmt.Errorf("cannot connect stage %T to %T", w, next)
	}

	w2.SetInputChannel(w.outputChan)
	return nil
}

var _ Stage = (*StageWorker[any, any])(nil)
var _ Consumer[any] = (*StageWorker[any, any])(nil)

type StageWorker[In any, Out any] struct {
	baseWorker[In, Out]
	processingFunc func(context.Context, In) []Out
}

func NewStage[In any, Out any](fun func(context.Context, In) []Out) *StageWorker[In, Out] {
	output := make(chan Out)
	return &StageWorker[In, Out]{
		baseWorker: baseWorker[In, Out]{
			outputChan:  output,
			concurrency: 1,
		},
		processingFunc: fun,
	}
}

func (w *StageWorker[In, Out]) Start(ctx context.Context) {
	for range w.concurrency {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case input, ok := <-w.inputChan:
					if !ok {
						return
					}
					for _, output := range w.processingFunc(ctx, input) {
						w.outputChan <- output
					}
				}
			}
		}()
	}
}

type BatchingStageWorker[In any] struct {
	baseWorker[In, []In]
	batchSize     int
	batchInterval time.Duration
	clock         clockwork.Clock
}

func NewBatchingStage[In any](batchInterval time.Duration, batchSize int) *BatchingStageWorker[In] {
	return NewBatchingStageWithClock[In](batchInterval, batchSize, clockwork.NewRealClock())
}

func NewBatchingStageWithClock[In any](batchInterval time.Duration, batchSize int, clock clockwork.Clock) *BatchingStageWorker[In] {
	output := make(chan []In)
	return &BatchingStageWorker[In]{
		baseWorker: baseWorker[In, []In]{
			outputChan:  output,
			concurrency: 1,
		},
		batchSize:     batchSize,
		batchInterval: batchInterval,
		clock:         clock,
	}
}

func (w *BatchingStageWorker[In]) Start(ctx context.Context) {
	for range w.concurrency {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			var batch []In
			var tickerChan <-chan time.Time
			if w.batchInterval > 0 {
				tickerChan = w.clock.NewTicker(w.batchInterval).Chan()
			}
			for {
				select {
				case <-ctx.Done():
					return
				case input, ok := <-w.inputChan:
					if !ok {
						if len(batch) > 0 {
							w.outputChan <- batch
						}
						return
					}
					batch = append(batch, input)
					if w.batchSize > 0 && len(batch) >= w.batchSize {
						w.outputChan <- batch
						batch = nil
					}
				case <-tickerChan:
					if len(batch) > 0 {
						w.outputChan <- batch
						batch = nil
					}
				}
			}
		}()
	}
}

type nullOutput struct{}

type SinkStageWorker[In any] struct {
	baseWorker[In, nullOutput]
	processingFunc func(context.Context, In)
}

func NewSinkStage[In any](fun func(context.Context, In)) *SinkStageWorker[In] {
	return &SinkStageWorker[In]{
		baseWorker: baseWorker[In, nullOutput]{
			concurrency: 1,
		},
		processingFunc: fun,
	}
}

func (w *SinkStageWorker[In]) Start(ctx context.Context) {
	for range w.concurrency {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case input, ok := <-w.inputChan:
					if !ok {
						return
					}
					w.processingFunc(ctx, input)
				}
			}
		}()
	}
}

type Pipeline interface {
	Start(ctx context.Context)
	Stop()
}

type pipeline[In any] struct {
	workers   []Stage
	inputChan chan In
}

func (p *pipeline[In]) Start(ctx context.Context) {
	for _, worker := range p.workers {
		worker.Start(ctx)
	}
}

func (p *pipeline[In]) Stop() {
	close(p.inputChan)
	for _, worker := range p.workers {
		worker.Stop()
	}
}

type Builder interface {
	AddStage(stage Stage, options ...StageOption) Builder
	Build() (Pipeline, error)
}

type pipelineBuilder[In any] struct {
	workers   []Stage
	inputChan chan In
}

func NewPipelineBuilder[In any](inputChan chan In) Builder {
	return &pipelineBuilder[In]{
		inputChan: inputChan,
	}
}

func (b *pipelineBuilder[In]) AddStage(stage Stage, options ...StageOption) Builder {
	b.workers = append(b.workers, stage)
	for _, option := range options {
		option(stage)
	}
	return b
}

func (b *pipelineBuilder[In]) Build() (Pipeline, error) {
	if len(b.workers) == 0 {
		return &pipeline[In]{
			workers:   nil,
			inputChan: b.inputChan,
		}, nil
	}

	w := b.workers[0]
	w2, ok := w.(Consumer[In])
	if !ok {
		return nil, fmt.Errorf("first stage %T must accept input %T", w, b.inputChan)
	}
	w2.SetInputChannel(b.inputChan)
	for i, worker := range b.workers[1:] {
		if err := b.workers[i].Connect(worker); err != nil {
			return nil, fmt.Errorf("cannot connect stage %d to stage %d: %w", i, i+1, err)
		}
	}
	return &pipeline[In]{
		workers:   b.workers,
		inputChan: b.inputChan,
	}, nil
}

type StageOption func(Stage)

func WithConcurrency(concurrency int) StageOption {
	return func(s Stage) {
		s.SetConcurrency(concurrency)
	}
}

func WithOutputChanSize(size int) StageOption {
	return func(s Stage) {
		s.SetOutputChanSize(size)
	}
}
