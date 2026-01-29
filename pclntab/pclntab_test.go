// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package pclntab

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func getGoToolChain(goMinorVersion int) string {
	suffix := ""
	if goMinorVersion >= 21 {
		suffix = ".0"
	}
	if goMinorVersion == 26 {
		suffix = "rc2"
	}
	return fmt.Sprintf("GOTOOLCHAIN=go1.%v%v", goMinorVersion, suffix)
}

func getTextStart(ef *pfelf.File) uint64 {
	var textStart uint64
	_ = ef.VisitSymbols(func(sym libpf.Symbol) bool {
		if sym.Name == "runtime.text" {
			textStart = uint64(sym.Address)
			return false
		}
		return true
	})
	return textStart
}

func TestGoPCLnTabExtraction(t *testing.T) {
	t.Parallel()
	disableRecover = true
	testDataDir := "../testdata"
	tests := map[string]struct {
		srcFile string
		pie     bool
		cgo     bool
	}{
		// helloworld is a very basic Go binary without special build flags.
		"std":     {srcFile: "helloworld.go"},
		"std.cgo": {srcFile: "helloworld_cgo.go", cgo: true},
		// helloworld.pie is a Go binary that is build with PIE enabled.
		"pie": {srcFile: "helloworld.go", pie: true},
		// helloworld.pie.cgo is a Go binary that is build with PIE enabled and with cgo,
		// in that case .gopclntab is stored in .data.rel.ro.gopclntab section and is merged with .data.rel.ro section by system linker (with Go < 1.26).
		"pie.cgo": {srcFile: "helloworld_cgo.go", pie: true, cgo: true},
	}

	tmpDir := t.TempDir()
	goMinorVersions := []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}
	for _, goMinorVersion := range goMinorVersions {
		for name, test := range tests {
			if goMinorVersion <= 12 && test.pie {
				continue
			}
			if runtime.GOARCH == "arm64" && goMinorVersion <= 8 {
				continue
			}
			if test.cgo && goMinorVersion <= 5 {
				continue
			}
			t.Run(fmt.Sprintf("go1.%v#%v", goMinorVersion, name), func(t *testing.T) {
				t.Parallel()
				exe := filepath.Join(tmpDir, fmt.Sprintf("%v.v1_%v.%v", strings.TrimRight(test.srcFile, ".go"), goMinorVersion, name))
				buildArgs := []string{"build", "-o", exe}
				if test.pie {
					buildArgs = append(buildArgs, "-buildmode=pie")
				}
				cmd := exec.CommandContext(t.Context(), "go", buildArgs...) // #nosec G204
				cmd.Args = append(cmd.Args, test.srcFile)
				cmd.Dir = testDataDir
				cmd.Env = append(cmd.Environ(), getGoToolChain(goMinorVersion))
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.String(), err, out)

				ef, err := pfelf.Open(exe)
				require.NoError(t, err)
				defer ef.Close()

				goPCLnTabInfo, err := findGoPCLnTab(ef, true)
				require.NoError(t, err)
				require.NotNil(t, goPCLnTabInfo)

				if goMinorVersion >= 18 {
					require.NotNil(t, goPCLnTabInfo.GoFuncAddr)
					textStart := getTextStart(ef)
					require.NotZero(t, textStart)
					require.Equal(t, textStart, goPCLnTabInfo.TextStart.Address)
				}

				exeStripped := exe + ".stripped"
				out, err = exec.CommandContext(t.Context(), "objcopy", "-S", exe, exeStripped).CombinedOutput() // #nosec G204
				require.NoError(t, err, "failed to rename section: %s\n%s", err, out)

				goPCLnTabInfo2, err := findGoPCLnTab(ef, true)
				require.NoError(t, err)
				require.NotNil(t, goPCLnTabInfo2)

				require.Equal(t, goPCLnTabInfo.GoFuncAddr, goPCLnTabInfo2.GoFuncAddr)
				require.Equal(t, goPCLnTabInfo.Address, goPCLnTabInfo2.Address)
				require.Equal(t, goPCLnTabInfo.TextStart.Address, goPCLnTabInfo2.TextStart.Address)
				require.GreaterOrEqual(t, len(goPCLnTabInfo2.Data), len(goPCLnTabInfo.Data))
				require.GreaterOrEqual(t, len(goPCLnTabInfo2.GoFuncData), len(goPCLnTabInfo.GoFuncData))
			})
		}
	}
}
