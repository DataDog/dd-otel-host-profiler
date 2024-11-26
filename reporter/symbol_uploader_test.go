// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"context"
	"debug/elf"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func checkGoPCLnTab(t *testing.T, filename string) {
	f, err := elf.Open(filename)
	require.NoError(t, err)
	defer f.Close()
	section := f.Section(".gopclntab")
	require.NotNil(t, section)
	require.Equal(t, elf.SHT_PROGBITS, section.Type)
	data, err := section.Data()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(data), 16)

	var quantum byte
	switch runtime.GOARCH {
	case "amd64":
		quantum = 0x1
	case "arm64":
		quantum = 0x4
	}

	expectedHeader := []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, quantum, 0x08}
	assert.Equal(t, expectedHeader, data[:8])
}

func TestGoPCLnTabExtraction(t *testing.T) {
	tests := map[string]struct {
		elfFile string
	}{
		// helloworld is a very basic Go binary without special build flags.
		"regular Go binary": {elfFile: "testdata/helloworld"},
		// helloworld.pie is a Go binary that is build with PIE enabled.
		"PIE Go binary": {elfFile: "testdata/helloworld.pie"},
		// helloworld.stripped.pie is a Go binary that is build with PIE enabled and all debug
		// information stripped.
		"stripped PIE Go binary": {elfFile: "testdata/helloworld.stripped.pie"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := pfelf.Open(test.elfFile)
			require.NoError(t, err)
			goPCLnTabInfo, err := findGoPCLnTab(f)
			require.NoError(t, err)
			assert.NotNil(t, goPCLnTabInfo)
			outputFile, err := os.CreateTemp("", "test")
			require.NoError(t, err)
			defer os.Remove(outputFile.Name())
			defer outputFile.Close()

			err = copySymbolsAndGoPCLnTab(context.Background(), test.elfFile, outputFile.Name(), goPCLnTabInfo)
			require.NoError(t, err)
			checkGoPCLnTab(t, outputFile.Name())
		})
	}
}
