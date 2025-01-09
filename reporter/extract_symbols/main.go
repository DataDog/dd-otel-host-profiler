// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package main

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

	"github.com/DataDog/dd-otel-host-profiler/reporter"
)

func extractDebugInfos(elfFile, outFile string) error {
	ef, err := pfelf.Open(elfFile)
	if err != nil {
		return fmt.Errorf("failed to open elf file: %w", err)
	}
	defer ef.Close()
	goPCLnTabInfo, err := reporter.FindGoPCLnTab(ef)
	if err != nil {
		return fmt.Errorf("failed to find pclntab: %w", err)
	}

	if goPCLnTabInfo != nil {
		fmt.Printf("Found GoPCLnTab at 0x%x, size %d, headerVersion: %v\n", goPCLnTabInfo.Address, len(goPCLnTabInfo.Data), goPCLnTabInfo.Version.String())
		fmt.Printf("Found GoFunc at 0x%x, size %d\n", goPCLnTabInfo.GoFuncAddr, len(goPCLnTabInfo.GoFuncData))
		return reporter.CopySymbolsAndGoPCLnTab(context.Background(), elfFile, outFile, goPCLnTabInfo)
	}
	return reporter.CopySymbols(context.Background(), elfFile, outFile)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <elf-file> <debug-file>\n", os.Args[0])
		return
	}

	elfFile := os.Args[1]
	outFile := os.Args[2]

	err := extractDebugInfos(elfFile, outFile)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
