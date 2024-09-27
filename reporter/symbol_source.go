// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import "fmt"

type SymbolSource int64

const (
	None SymbolSource = iota
	DynamicSymbolTable
	SymbolTable
	DebugInfo
)

func (s SymbolSource) String() string {
	switch s {
	case None:
		return "none"
	case DynamicSymbolTable:
		return "dynamic_symbol_table"
	case SymbolTable:
		return "symbol_table"
	case DebugInfo:
		return "debug_info"
	}
	return "unknown"
}

func NewSymbolSource(s string) (SymbolSource, error) {
	switch s {
	case "none":
		return None, nil
	case "dynamic_symbol_table":
		return DynamicSymbolTable, nil
	case "symbol_table":
		return SymbolTable, nil
	case "debug_info":
		return DebugInfo, nil
	}
	return None, fmt.Errorf("unknown symbol source: %s", s)
}
