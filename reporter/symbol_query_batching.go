// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"context"
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	samples "github.com/DataDog/dd-otel-host-profiler/reporter/samples"
	"github.com/DataDog/dd-otel-host-profiler/reporter/symbol"
)

type SymbolQueryBatch []*symbol.Elf

type SymbolQueryResult struct {
	SymbolSource symbol.Source
	Err          error
}

type ElfWithBackendSources struct {
	*symbol.Elf
	BackendSymbolSources []SymbolQueryResult
}

func invokeQuerier(ctx context.Context, buildIDs []string, arch string, querier SymbolQuerier, ind int,
	buildIDToResult map[string][]*ElfWithBackendSources) {
	symbolFiles, err := querier.QuerySymbols(ctx, buildIDs, arch)
	if err != nil {
		for _, results := range buildIDToResult {
			for _, result := range results {
				result.BackendSymbolSources[ind].Err = fmt.Errorf("failed to query symbols: %w", err)
			}
		}
		return
	}

	// Note that the same buildID can appear multiple times in the symbolFiles with different buildIDTypes
	// because there is no constraint in sourcemap DB that prevents having identical goBuildID, gnuBuildID
	// of fileHash for the same or a different executable.
	// For a given buildID though, the backend will return first the matching gnuBuildID, then goBuildID and
	// finally fileHash if they exist.
	// That's why we consider the first symbol source for a given buildID and ignore the rest.
	for _, symbolFile := range symbolFiles {
		for _, result := range buildIDToResult[symbolFile.BuildID] {
			queryResult := &result.BackendSymbolSources[ind]
			if queryResult.Err != nil || queryResult.SymbolSource != symbol.SourceNone {
				// Already set or an error occurred, skips
				continue
			}
			src, err := symbol.NewSource(symbolFile.SymbolSource)
			if err != nil {
				result.BackendSymbolSources[ind].Err = fmt.Errorf("failed to parse symbol source: %w", err)
			} else {
				result.BackendSymbolSources[ind].SymbolSource = src
			}
		}
	}
}

func (e *ElfWithBackendSources) fillWithError(err error) {
	for i := range e.BackendSymbolSources {
		e.BackendSymbolSources[i].Err = err
	}
}

func ExecuteSymbolQueryBatch(ctx context.Context, batch SymbolQueryBatch, queriers []SymbolQuerier) []ElfWithBackendSources {
	if len(batch) == 0 {
		return nil
	}

	log.Infof("Querying symbols for %d executables", len(batch))
	buildIDToResult := make(map[string][]*ElfWithBackendSources)

	// All the elfs in the batch are expected to have the same arch
	arch := batch[0].Arch()

	elfResults := make([]ElfWithBackendSources, 0, len(batch))

	for _, e := range batch {
		elfResults = append(elfResults,
			ElfWithBackendSources{Elf: e, BackendSymbolSources: make([]SymbolQueryResult, len(queriers))})

		result := &elfResults[len(elfResults)-1]
		if e.Arch() != arch {
			result.fillWithError(fmt.Errorf("arch mismatch: expected %s, got %s", arch, e.Arch()))
			continue
		}

		buildID := samples.GetBuildID(e.GnuBuildID(), e.GoBuildID(), e.FileID())
		if buildID == "" {
			result.fillWithError(errors.New("empty buildID"))
			continue
		}
		buildIDToResult[buildID] = append(buildIDToResult[buildID], result)
	}

	buildIDs := make([]string, 0, len(buildIDToResult))
	for buildID := range buildIDToResult {
		buildIDs = append(buildIDs, buildID)
	}

	if len(queriers) == 1 {
		invokeQuerier(ctx, buildIDs, arch, queriers[0], 0, buildIDToResult)
	} else {
		var wg sync.WaitGroup
		for i, querier := range queriers {
			wg.Add(1)
			go func(i int, querier SymbolQuerier) {
				defer wg.Done()
				invokeQuerier(ctx, buildIDs, arch, querier, i, buildIDToResult)
			}(i, querier)
		}
		wg.Wait()
	}

	return elfResults
}
