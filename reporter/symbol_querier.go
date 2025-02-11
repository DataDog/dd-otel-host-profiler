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
	"golang.org/x/time/rate"
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

type DatadogSymbolQuerier struct {
	ddAPIKey       string
	ddAPPKey       string
	symbolQueryURL string

	client *http.Client
}

func NewDatadogSymbolQuerier(ddSite, ddAPIKey, ddAPPKey string) (*DatadogSymbolQuerier, error) {
	symbolQueryURL, err := url.JoinPath("https://api."+ddSite, symbolQueryEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return &DatadogSymbolQuerier{
		ddAPIKey:       ddAPIKey,
		ddAPPKey:       ddAPPKey,
		symbolQueryURL: symbolQueryURL,
		client:         &http.Client{Timeout: uploadTimeout},
	}, nil
}

func (d *DatadogSymbolQuerier) QuerySymbols(ctx context.Context, buildIDs []string,
	arch string) ([]SymbolFile, error) {
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
		return nil, fmt.Errorf("error while querying symbols: %s, %s", resp.Status, string(respBody))
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

	results []SymbolFile
	err     error
}

type BatchSymbolQuerier struct {
	waitForMoreQueriesDuration time.Duration
	maxQueryLatency            time.Duration

	querier *DatadogSymbolQuerier

	rateLimiter *rate.Limiter
	batchChan   chan *batchedQuery
	done        chan struct{}
}

type BatchSymbolQuerierConfig struct {
	// Time to wait for more queries before executing the current batch.
	WaitForMoreQueriesDuration time.Duration
	// Average wait time between batches: QPS for rate limiter is derived from this, and it also limits the total wait time for new queries.
	AvgMinDurationBetwenBatches time.Duration

	// Allowed burst for rate limiting.
	Burst int

	Querier *DatadogSymbolQuerier
}

func NewBatchSymbolQuerier(config BatchSymbolQuerierConfig) *BatchSymbolQuerier {
	return &BatchSymbolQuerier{
		waitForMoreQueriesDuration: config.WaitForMoreQueriesDuration,
		maxQueryLatency:            config.AvgMinDurationBetwenBatches,
		rateLimiter:                rate.NewLimiter(rate.Limit(time.Second/config.AvgMinDurationBetwenBatches), config.Burst),
		querier:                    config.Querier,
		batchChan:                  make(chan *batchedQuery),
	}
}

func (b *BatchSymbolQuerier) doQuery(ctx context.Context, buildIDs []string, arch string, queries []*batchedQuery) {
	symbolFiles, err := b.querier.QuerySymbols(ctx, buildIDs, arch)

	if err != nil {
		for _, query := range queries {
			if query.arch == arch {
				query.err = err
			}
		}
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
						query.results = append(query.results, *symbolFile)
					}
				}
			}
		}
	}
}

func (b *BatchSymbolQuerier) doQueries(ctx context.Context, queries []*batchedQuery) {
	// There should be only a single arch, but be safe
	buildIDsByArch := make(map[string][]string)

	for _, query := range queries {
		buildIDsByArch[query.arch] = append(buildIDsByArch[query.arch], query.buildIDs...)
	}

	for arch, buildIDs := range buildIDsByArch {
		b.doQuery(ctx, buildIDs, arch, queries)
	}
	close(b.done)
	b.done = make(chan struct{})
}

func (b *BatchSymbolQuerier) Start(ctx context.Context) {
	go func() {
		var queries []*batchedQuery
		b.done = make(chan struct{})

		var limiterChan <-chan time.Time
		var lastQueryTime time.Time
		var firstQueryTime time.Time

		for {
			doCall := false
			select {
			case <-ctx.Done():
				return
			case query := <-b.batchChan:
				if len(queries) == 0 {
					firstQueryTime = time.Now()
				}
				queries = append(queries, query)
				if limiterChan == nil {
					r := b.rateLimiter.Reserve()
					delay := r.Delay()
					if delay > 0 {
						limiterChan = time.After(delay)
					} else {
						limiterChan = time.After(b.waitForMoreQueriesDuration)
					}
				}
				lastQueryTime = time.Now()
			case <-limiterChan:
				if t := time.Since(lastQueryTime); t < b.waitForMoreQueriesDuration && time.Since(firstQueryTime) < b.maxQueryLatency {
					limiterChan = time.After(b.waitForMoreQueriesDuration)
				} else {
					doCall = true
					limiterChan = nil
				}
			}
			if doCall {
				b.doQueries(ctx, queries)
				queries = queries[:0]
			}
		}
	}()
}

func (b *BatchSymbolQuerier) QuerySymbols(ctx context.Context, buildIDs []string, arch string) ([]SymbolFile, error) {
	query := &batchedQuery{
		buildIDs: buildIDs,
		arch:     arch,
	}

	b.batchChan <- query

	select {
	case <-b.done:
		return query.results, query.err
	case <-ctx.Done():
		return nil, nil
	}
}
