// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

type SymbolEndpoint struct {
	Site   string `json:"site"`
	APIKey string `json:"api_key"`
	AppKey string `json:"app_key"`
}
