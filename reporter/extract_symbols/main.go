package main

import (
	"context"
	"fmt"
	"os"

	"github.com/DataDog/dd-otel-host-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func extractDebugInfos(elfFile, outFile string) error {
	ef, err := pfelf.Open(elfFile)
	if err != nil {
		return fmt.Errorf("failed to open elf file: %v", err)
	}
	defer ef.Close()
	goPCLnTabInfo, err := reporter.FindGoPCLnTab(ef, true)
	if err != nil {
		return fmt.Errorf("failed to find pclntab: %v", err)
	}

	if goPCLnTabInfo != nil {
		fmt.Printf("Found GoPCLnTab at 0x%x, size %d\n", goPCLnTabInfo.Address, len(goPCLnTabInfo.Data))
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
