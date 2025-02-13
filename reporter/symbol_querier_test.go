// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"cmp"
	"context"
	"errors"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

const symbolQueryInterval = 5 * time.Second

type key struct {
	buildID string
	arch    string
}

type symbolMap map[key]SymbolFile
type errorMap map[string]error

type mockSymbolQuerier struct {
	m      symbolMap
	e      errorMap
	ncalls int
}

func (m *mockSymbolQuerier) QuerySymbols(_ context.Context, buildIDs []string, arch string) ([]SymbolFile, error) {
	m.ncalls++
	if err, ok := m.e[arch]; ok {
		return nil, err
	}
	var symbolFiles []SymbolFile
	for _, buildID := range buildIDs {
		if sym, ok := m.m[key{buildID, arch}]; ok {
			symbolFiles = append(symbolFiles, sym)
		}
	}
	// randomly shuffle the results
	for i := range symbolFiles {
		j := rand.Intn(i + 1) //nolint:gosec
		symbolFiles[i], symbolFiles[j] = symbolFiles[j], symbolFiles[i]
	}
	return symbolFiles, nil
}

func (m *mockSymbolQuerier) ResetCallCount() int {
	n := m.ncalls
	m.ncalls = 0
	return n
}

func (m *mockSymbolQuerier) Start(_ context.Context) {}

func sortSymbolFiles(symbolFiles []SymbolFile) []SymbolFile {
	slices.SortFunc(symbolFiles, func(a, b SymbolFile) int {
		return cmp.Or(cmp.Compare(a.BuildID, b.BuildID),
			cmp.Compare(a.SymbolSource, b.SymbolSource),
			cmp.Compare(a.BuildIDType, b.BuildIDType))
	})
	return symbolFiles
}

func TestBatchSymbolQuerier_Multiplexing(t *testing.T) {
	m := symbolMap{
		{buildID: "build1", arch: "arch1"}: {BuildID: "build1", SymbolSource: "source1", BuildIDType: "type1"},
		{buildID: "build2", arch: "arch1"}: {BuildID: "build2", SymbolSource: "source2", BuildIDType: "type2"},
		{buildID: "build3", arch: "arch1"}: {BuildID: "build3", SymbolSource: "source3", BuildIDType: "type3"},
		{buildID: "build1", arch: "arch2"}: {BuildID: "build1", SymbolSource: "source4", BuildIDType: "type4"},
		{buildID: "build2", arch: "arch2"}: {BuildID: "build2", SymbolSource: "source5", BuildIDType: "type5"},
	}

	querier := &mockSymbolQuerier{m: m}

	clock := clockwork.NewFakeClock()
	batchQuerier := NewBatchSymbolQuerierWithClock(BatchSymbolQuerierConfig{
		BatchInterval: symbolQueryInterval,
		Querier:       querier,
	}, clock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batchQuerier.Start(ctx)

	// Query symbols for multiple archs with duplicate buildIDs/arch
	chan1 := batchQuerier.QuerySymbolsChannel([]string{"build1", "build2"}, "arch1")
	chan2 := batchQuerier.QuerySymbolsChannel([]string{"build2", "build3"}, "arch1")
	chan3 := batchQuerier.QuerySymbolsChannel([]string{"build1"}, "arch2")
	chan4 := batchQuerier.QuerySymbolsChannel([]string{"build4"}, "arch2")

	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	clock.Advance(symbolQueryInterval)

	r := <-chan1
	require.NoError(t, r.Err)
	require.Equal(t, sortSymbolFiles([]SymbolFile{m[key{"build1", "arch1"}], m[key{"build2", "arch1"}]}), sortSymbolFiles(r.SymbolFiles))
	r = <-chan2
	require.NoError(t, r.Err)
	require.Equal(t, sortSymbolFiles([]SymbolFile{m[key{"build2", "arch1"}], m[key{"build3", "arch1"}]}), sortSymbolFiles(r.SymbolFiles))
	r = <-chan3
	require.NoError(t, r.Err)
	require.Equal(t, []SymbolFile{m[key{"build1", "arch2"}]}, r.SymbolFiles)
	r = <-chan4
	require.NoError(t, r.Err)
	require.Empty(t, r.SymbolFiles)

	require.Equal(t, 2, querier.ResetCallCount()) // 2 calls, one for each arch

	// Query symbols for multiple archs with error for one arch
	querier.e = errorMap{"arch1": errors.New("error")}
	chan1 = batchQuerier.QuerySymbolsChannel([]string{"build1", "build2"}, "arch1")
	chan2 = batchQuerier.QuerySymbolsChannel([]string{"build2", "build3"}, "arch1")
	chan3 = batchQuerier.QuerySymbolsChannel([]string{"build1"}, "arch2")
	chan4 = batchQuerier.QuerySymbolsChannel([]string{"build4"}, "arch2")

	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	clock.Advance(symbolQueryInterval)

	r = <-chan1
	require.Error(t, r.Err)
	require.Empty(t, r.SymbolFiles)
	r = <-chan2
	require.Error(t, r.Err)
	require.Empty(t, r.SymbolFiles)
	r = <-chan3
	require.NoError(t, r.Err)
	require.Equal(t, []SymbolFile{m[key{"build1", "arch2"}]}, r.SymbolFiles)
	r = <-chan4
	require.NoError(t, r.Err)
	require.Empty(t, r.SymbolFiles)

	require.Equal(t, 2, querier.ResetCallCount()) // 2 calls, one for each arch
}

func TestBatchSymbolQuerier_Batching(t *testing.T) {
	m := symbolMap{
		{buildID: "build1", arch: "arch1"}: {BuildID: "build1", SymbolSource: "source1", BuildIDType: "type1"},
	}

	querier := &mockSymbolQuerier{m: m}

	clock := clockwork.NewFakeClock()
	batchQuerier := NewBatchSymbolQuerierWithClock(BatchSymbolQuerierConfig{
		BatchInterval: symbolQueryInterval,
		Querier:       querier,
	}, clock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batchQuerier.Start(ctx)

	chan1 := batchQuerier.QuerySymbolsChannel([]string{"build1"}, "arch1")

	// Batcher should wait `symbolQueryInterval` before doing call
	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	clock.Advance(symbolQueryInterval - 1*time.Millisecond)
	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	require.Equal(t, 0, querier.ResetCallCount())
	clock.Advance(1 * time.Millisecond)

	r := <-chan1
	require.NoError(t, r.Err)
	require.Equal(t, []SymbolFile{m[key{"build1", "arch1"}]}, r.SymbolFiles)
	require.Equal(t, 1, querier.ResetCallCount())

	// Batcher should wait 1000ms before sending another batch
	chan1 = batchQuerier.QuerySymbolsChannel([]string{"build1"}, "arch1")
	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	clock.Advance(symbolQueryInterval - 1*time.Millisecond)
	require.Equal(t, 0, querier.ResetCallCount())
	clock.Advance(1 * time.Millisecond)
	r = <-chan1
	require.NoError(t, r.Err)
	require.Equal(t, 1, querier.ResetCallCount())

	// Batcher should aggregate queries and wait 1000ms before sending another batch
	chan1 = batchQuerier.QuerySymbolsChannel([]string{"build1"}, "arch1")
	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	clock.Advance(symbolQueryInterval / 10)
	chan2 := batchQuerier.QuerySymbolsChannel([]string{"build1"}, "arch1")
	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	clock.Advance(symbolQueryInterval / 10)
	chan3 := batchQuerier.QuerySymbolsChannel([]string{"build1"}, "arch1")
	require.NoError(t, clock.BlockUntilContext(ctx, 1))
	clock.Advance(symbolQueryInterval*8/10 - 1*time.Millisecond)
	require.Equal(t, 0, querier.ResetCallCount())
	clock.Advance(1 * time.Millisecond)
	r = <-chan1
	require.NoError(t, r.Err)
	r = <-chan2
	require.NoError(t, r.Err)
	r = <-chan3
	require.NoError(t, r.Err)
	require.Equal(t, 1, querier.ResetCallCount())
}
