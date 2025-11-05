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
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func getGoToolChain(goMinorVersion int) string {
	if goMinorVersion < 21 {
		return fmt.Sprintf("GOTOOLCHAIN=go1.%v", goMinorVersion)
	}
	return fmt.Sprintf("GOTOOLCHAIN=go1.%v.0", goMinorVersion)
}

func TestGoPCLnTabExtraction(t *testing.T) {
	t.Parallel()
	disableRecover = true
	testDataDir := "../testdata"
	srcFile := "helloworld.go"
	tests := map[string]struct {
		buildArgs []string
	}{
		// helloworld is a very basic Go binary without special build flags.
		"std": {},
		// helloworld.pie is a Go binary that is build with PIE enabled.
		"pie": {buildArgs: []string{"-buildmode=pie"}},
		// helloworld.stripped.pie is a Go binary that is build with PIE enabled and all debug
		// information stripped.
		"pie.sw": {buildArgs: []string{"-buildmode=pie", "-ldflags=-s -w"}},
	}

	tmpDir := t.TempDir()
	goMinorVersions := []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
	for _, goMinorVersion := range goMinorVersions {
		for name, test := range tests {
			if goMinorVersion <= 12 && strings.HasPrefix(name, "pie") {
				continue
			}
			if runtime.GOARCH == "arm64" && goMinorVersion <= 8 {
				continue
			}
			t.Run(fmt.Sprintf("go1.%v#%v", goMinorVersion, name), func(t *testing.T) {
				t.Parallel()
				exe := filepath.Join(tmpDir, fmt.Sprintf("%v.v1_%v.%v", strings.TrimRight(srcFile, ".go"), goMinorVersion, name))
				cmd := exec.CommandContext(t.Context(), "go", append([]string{"build", "-o", exe}, test.buildArgs...)...) // #nosec G204
				cmd.Args = append(cmd.Args, srcFile)
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
				}

				exeStripped := exe + ".stripped"
				out, err = exec.CommandContext(t.Context(), "objcopy", "-S", "--rename-section", ".data.rel.ro.gopclntab=.foo1", "--rename-section", ".gopclntab=.foo2", exe, exeStripped).CombinedOutput() // #nosec G204
				require.NoError(t, err, "failed to rename section: %s\n%s", err, out)

				goPCLnTabInfo2, err := findGoPCLnTab(ef, true)
				require.NoError(t, err)
				require.NotNil(t, goPCLnTabInfo2)

				require.Equal(t, goPCLnTabInfo.GoFuncAddr, goPCLnTabInfo2.GoFuncAddr)
				require.Equal(t, goPCLnTabInfo.Address, goPCLnTabInfo2.Address)
				require.GreaterOrEqual(t, len(goPCLnTabInfo2.Data), len(goPCLnTabInfo.Data))
				require.GreaterOrEqual(t, len(goPCLnTabInfo2.GoFuncData), len(goPCLnTabInfo.GoFuncData))
			})
		}
	}
}
