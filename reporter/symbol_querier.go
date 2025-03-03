// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/DataDog/jsonapi"
	"github.com/jonboulle/clockwork"
)

const symbolQueryEndpoint = "/api/v2/profiles/symbols/query"

type SymbolFile struct {
	ID           string `json:"id" jsonapi:"primary,symbols-query-response"`
	BuildID      string `json:"buildId" jsonapi:"attribute"`
	SymbolSource string `json:"symbolSource" jsonapi:"attribute"`
	BuildIDType  string `json:"buildIdType" jsonapi:"attribute"`
}

type SymbolsQueryRequest struct {
	ID       string   `jsonapi:"primary,symbols-query-request"`
	BuildIDs []string `json:"buildIds" jsonapi:"attribute" validate:"required"`
	Arch     string   `json:"arch" jsonapi:"attribute" validate:"required"`
}

type DatadogSymbolQuerier interface {
	Start(ctx context.Context)
	QuerySymbols(ctx context.Context, buildIDs []string, arch string) ([]SymbolFile, error)
	ResetCallCount() int
}

type datadogSymbolQuerier struct {
	ddAPIKey       string
	ddAPPKey       string
	symbolQueryURL string

	client    *http.Client
	callCount int
}

func NewDatadogSymbolQuerier(ddSite, ddAPIKey, ddAPPKey string) (DatadogSymbolQuerier, error) {
	symbolQueryURL, err := url.JoinPath("https://api."+ddSite, symbolQueryEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return &datadogSymbolQuerier{
		ddAPIKey:       ddAPIKey,
		ddAPPKey:       ddAPPKey,
		symbolQueryURL: symbolQueryURL,
		client:         &http.Client{Timeout: uploadTimeout},
	}, nil
}

func (d *datadogSymbolQuerier) Start(_ context.Context) {
	// No-op
}

func (d *datadogSymbolQuerier) ResetCallCount() int {
	count := d.callCount
	d.callCount = 0
	return count
}

func (d *datadogSymbolQuerier) QuerySymbols(ctx context.Context, buildIDs []string,
	arch string) ([]SymbolFile, error) {
	d.callCount++
	symbolsQueryRequest := &SymbolsQueryRequest{
		ID:       "symbols-query-request",
		BuildIDs: buildIDs,
		Arch:     arch,
	}

	body, err := jsonapi.Marshal(symbolsQueryRequest)
	if err != nil {
		return nil, fmt.Errorf("error marshaling symbols query request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.symbolQueryURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Dd-Api-Key", d.ddAPIKey)
	req.Header.Set("Dd-Application-Key", d.ddAPPKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error while querying symbols from %s: %s, %s", d.symbolQueryURL, resp.Status, string(respBody))
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var response []SymbolFile
	if err = jsonapi.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("error unmarshalling symbols query response: %w", err)
	}

	return response, nil
}

type batchedQuery struct {
	buildIDs []string
	arch     string

	result BatchQueryResult
	done   chan BatchQueryResult
}

func (q *batchedQuery) reportResult() {
	q.done <- q.result
}

type BatchQueryResult struct {
	SymbolFiles []SymbolFile
	Err         error
}

type BatchSymbolQuerier struct {
	batchInterval time.Duration

	querier DatadogSymbolQuerier

	batchChan chan *batchedQuery
	clock     clockwork.Clock
}

type BatchSymbolQuerierConfig struct {
	//  The interval at which to batch queries
	BatchInterval time.Duration

	Querier DatadogSymbolQuerier
}

func NewBatchSymbolQuerier(config BatchSymbolQuerierConfig) *BatchSymbolQuerier {
	return NewBatchSymbolQuerierWithClock(config, clockwork.NewRealClock())
}

func NewBatchSymbolQuerierWithClock(config BatchSymbolQuerierConfig, clock clockwork.Clock) *BatchSymbolQuerier {
	return &BatchSymbolQuerier{
		batchInterval: config.BatchInterval,
		querier:       config.Querier,
		batchChan:     make(chan *batchedQuery),
		clock:         clock,
	}
}

func (b *BatchSymbolQuerier) doQuery(ctx context.Context, buildIDs []string, arch string, queries []*batchedQuery) {
	symbolFiles, err := b.querier.QuerySymbols(ctx, buildIDs, arch)

	if err != nil {
		for _, query := range queries {
			if query.arch == arch {
				query.result = BatchQueryResult{Err: err}
			}
		}
		return
	}

	m := make(map[string][]*SymbolFile)
	for i, symbolFile := range symbolFiles {
		m[symbolFile.BuildID] = append(m[symbolFile.BuildID], &symbolFiles[i])
	}

	for _, query := range queries {
		if query.arch == arch {
			for _, buildID := range query.buildIDs {
				if symbolFiles, ok := m[buildID]; ok {
					for _, symbolFile := range symbolFiles {
						query.result.SymbolFiles = append(query.result.SymbolFiles, *symbolFile)
					}
				}
			}
		}
	}
}

func (b *BatchSymbolQuerier) doQueries(ctx context.Context, queries []*batchedQuery) {
	// There should be only a single arch, but be safe
	buildIDsByArch := make(map[string][]string)
	type key struct {
		buildID string
		arch    string
	}
	uniqueKeys := make(map[key]struct{})

	for _, query := range queries {
		for _, buildID := range query.buildIDs {
			// deduplicate (buildID,arch) pairs
			if _, ok := uniqueKeys[key{buildID, query.arch}]; !ok {
				uniqueKeys[key{buildID, query.arch}] = struct{}{}
				buildIDsByArch[query.arch] = append(buildIDsByArch[query.arch], buildID)
			}
		}
	}

	for arch, buildIDs := range buildIDsByArch {
		b.doQuery(ctx, buildIDs, arch, queries)
	}
}

func (b *BatchSymbolQuerier) Start(ctx context.Context) {
	go func() {
		var queries []*batchedQuery
		ticker := b.clock.NewTicker(b.batchInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case query := <-b.batchChan:
				queries = append(queries, query)
			case <-ticker.Chan():
				if len(queries) > 0 {
					b.doQueries(ctx, queries)
					for _, query := range queries {
						query.reportResult()
					}
					queries = queries[:0]
				}
			}
		}
	}()
}

func (b *BatchSymbolQuerier) QuerySymbolsChannel(buildIDs []string, arch string) <-chan BatchQueryResult {
	query := &batchedQuery{
		buildIDs: buildIDs,
		arch:     arch,
		done:     make(chan BatchQueryResult, 1),
	}

	b.batchChan <- query
	return query.done
}

func (b *BatchSymbolQuerier) QuerySymbols(ctx context.Context, buildIDs []string, arch string) ([]SymbolFile, error) {
	select {
	case result := <-b.QuerySymbolsChannel(buildIDs, arch):
		return result.SymbolFiles, result.Err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *BatchSymbolQuerier) ResetCallCount() int {
	return b.querier.ResetCallCount()
}
