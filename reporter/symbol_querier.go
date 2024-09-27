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

	"github.com/DataDog/jsonapi"
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

	fmt.Printf("Querying symbols with request: %s\n", string(body))

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