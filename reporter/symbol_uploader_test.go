// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/zstd"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
	"github.com/DataDog/dd-otel-host-profiler/reporter/symbol"
)

func findSymbol(f *elf.File, name string) *elf.Symbol {
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	for _, sym := range syms {
		if sym.Name == name {
			return &sym
		}
	}
	return nil
}

func findDynamicSymbol(f *elf.File, name string) *elf.Symbol {
	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil
	}
	for _, sym := range syms {
		if sym.Name == name {
			return &sym
		}
	}
	return nil
}

func checkGoPCLnTab(t *testing.T, f *elf.File, checkGoFunc bool) {
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

	if checkGoFunc {
		section = f.Section(".gofunc")
		require.NotNil(t, section)
		require.Equal(t, elf.SHT_PROGBITS, section.Type)
		require.NotNil(t, findSymbol(f, "go:func.*"))
	}
}

func checkGoPCLnTabExtraction(t *testing.T, filename, tmpDir string) {
	ef, err := pfelf.Open(filename)
	require.NoError(t, err)
	defer ef.Close()

	goPCLnTabInfo, err := pclntab.FindGoPCLnTab(ef)
	require.NoError(t, err)
	assert.NotNil(t, goPCLnTabInfo)

	outputFile := filepath.Join(tmpDir, "output.dbg")
	err = CopySymbols(context.Background(), filename, outputFile, goPCLnTabInfo, nil)
	require.NoError(t, err)
	f, err := elf.Open(outputFile)
	require.NoError(t, err)
	defer f.Close()
	checkGoPCLnTab(t, f, true)
}

func checkRequest(t *testing.T, req *http.Request, expectedSymbolSource symbol.Source) {
	reader := zstd.NewReader(req.Body)
	defer reader.Close()

	require.Equal(t, "zstd", req.Header.Get("Content-Encoding"))
	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	require.NoError(t, err)
	boundary, ok := params["boundary"]
	require.True(t, ok)
	mr := multipart.NewReader(reader, boundary)
	form, err := mr.ReadForm(1 << 20) // 1 MiB
	require.NoError(t, err)
	fhs, ok := form.File["elf_symbol_file"]
	require.True(t, ok)
	f, err := fhs[0].Open()
	require.NoError(t, err)
	defer f.Close()

	event, ok := form.File["event"]
	require.True(t, ok)
	e, err := event[0].Open()
	require.NoError(t, err)
	defer e.Close()

	// unmarshal json into map[string]string
	// check that the symbol source is correct
	result := make(map[string]string)
	err = json.NewDecoder(e).Decode(&result)
	require.NoError(t, err)
	require.Equal(t, expectedSymbolSource.String(), result["symbol_source"])

	elfFile, err := elf.NewFile(f)
	require.NoError(t, err)
	defer elfFile.Close()

	require.NoError(t, err)
	switch expectedSymbolSource {
	case symbol.SourceGoPCLnTab:
		checkGoPCLnTab(t, elfFile, true)
	case symbol.SourceDynamicSymbolTable:
		require.NotNil(t, findDynamicSymbol(elfFile, "foo"))
	}
}

func TestGoPCLnTabExtraction(t *testing.T) {
	t.Parallel()
	srcFile := "../testdata/helloworld.go"
	tests := map[string]struct {
		buildArgs []string
	}{
		// helloworld is a very basic Go binary without special build flags.
		"regular": {},
		// helloworld.pie is a Go binary that is build with PIE enabled.
		"pie": {buildArgs: []string{"-buildmode=pie"}},
		// helloworld.stripped.pie is a Go binary that is build with PIE enabled and all debug
		// information stripped.
		"stripped.pie": {buildArgs: []string{"-buildmode=pie", "-ldflags=-s -w"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tmpDir := t.TempDir()
			exe := filepath.Join(tmpDir, strings.TrimRight(srcFile, ".go")+"."+name)
			cmd := exec.Command("go", append([]string{"build", "-o", exe}, test.buildArgs...)...) // #nosec G204
			cmd.Args = append(cmd.Args, srcFile)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.Args, err, out)

			checkGoPCLnTabExtraction(t, exe, tmpDir)

			exeStripped := exe + ".stripped"
			out, err = exec.Command("objcopy", "-S", "--rename-section", ".data.rel.ro.gopclntab=.foo1", "--rename-section", ".gopclntab=.foo2", exe, exeStripped).CombinedOutput() // #nosec G204
			require.NoError(t, err, "failed to rename section: %s\n%s", err, out)
			checkGoPCLnTabExtraction(t, exeStripped, tmpDir)
		})
	}
}

func newTestUploader(uploadDynamicSymbols, uploadGoPCLnTab bool) (*DatadogSymbolUploader, error) {
	cfg := &SymbolUploaderConfig{
		Enabled:              true,
		UploadDynamicSymbols: uploadDynamicSymbols,
		UploadGoPCLnTab:      uploadGoPCLnTab,
		SymbolQueryInterval:  0,
		SymbolEndpoints: []SymbolEndpoint{
			{
				Site:   "foobar.com",
				APIKey: "api_key",
				AppKey: "app_key",
			},
			{
				Site:   "staging.com",
				APIKey: "api_key2",
				AppKey: "app_key2",
			},
		},
	}
	return NewDatadogSymbolUploader(cfg)
}

type DummyOpener struct{}

func (o *DummyOpener) Open(path string) (reader process.ReadAtCloser, actualPath string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	return f, fmt.Sprintf("/proc/%v/fd/%v", os.Getpid(), f.Fd()), nil
}

func buildGoExeWithoutDebugInfos(t *testing.T, tmpDir string) string {
	f, err := os.CreateTemp(tmpDir, "helloworld")
	require.NoError(t, err)
	defer f.Close()

	exe := f.Name()
	cmd := exec.Command("go", "build", "-o", exe, "-ldflags=-s -w", "../testdata/helloworld.go") // #nosec G204
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.Args, err, out)
	return exe
}

func buildExeWithDynamicSymbols(t *testing.T, tmpDir string) string {
	f, err := os.CreateTemp(tmpDir, "foo")
	require.NoError(t, err)
	defer f.Close()
	srcFile := "../testdata/foo.c"

	exe := f.Name()
	cmd := exec.Command("gcc", "-Wl,--strip-all", "-shared", "-o", exe, srcFile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.Args, err, out)

	return exe
}

//nolint:tparallel
func TestSymbolUpload(t *testing.T) {
	t.Parallel()
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	c1 := make(chan *http.Request)
	c2 := make(chan *http.Request)
	httpmock.RegisterResponder("POST", buildSymbolQueryURL("foobar.com"),
		httpmock.NewStringResponder(200, `{"data": []}`))
	httpmock.RegisterResponder("POST", buildSourcemapIntakeURL("foobar.com"),
		func(req *http.Request) (*http.Response, error) {
			c1 <- req
			return httpmock.NewStringResponse(200, ""), nil
		})
	httpmock.RegisterResponder("POST", buildSymbolQueryURL("staging.com"),
		httpmock.NewStringResponder(200, `{"data": []}`))
	httpmock.RegisterResponder("POST", buildSourcemapIntakeURL("staging.com"),
		func(req *http.Request) (*http.Response, error) {
			c2 <- req
			return httpmock.NewStringResponse(200, ""), nil
		})
	checkCallCount := func(t *testing.T, expected int) {
		callCountInfo := httpmock.GetCallCountInfo()
		assert.Equal(t, expected, callCountInfo["POST "+buildSymbolQueryURL("foobar.com")])
		assert.Equal(t, expected, callCountInfo["POST "+buildSourcemapIntakeURL("foobar.com")])
		assert.Equal(t, expected, callCountInfo["POST "+buildSymbolQueryURL("staging.com")])
		assert.Equal(t, expected, callCountInfo["POST "+buildSourcemapIntakeURL("staging.com")])
	}

	goExeWithoutDebugInfos := buildGoExeWithoutDebugInfos(t, t.TempDir())

	t.Run("No upload when no symbols", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(false, false)
		require.NoError(t, err)
		uploader.Start(context.Background())

		uploader.UploadSymbols(libpf.FileID{}, goExeWithoutDebugInfos, "build_id", &DummyOpener{})
		uploader.Stop()

		assert.Equal(t, 0, httpmock.GetTotalCallCount())
	})

	t.Run("Upload pclntab when enabled", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		uploader, err := newTestUploader(false, true)
		require.NoError(t, err)
		uploader.Start(ctx)
		uploader.UploadSymbols(libpf.FileID{}, goExeWithoutDebugInfos, "build_id", &DummyOpener{})
		req1 := <-c1
		req2 := <-c2
		checkRequest(t, req1, symbol.SourceGoPCLnTab)
		checkRequest(t, req2, symbol.SourceGoPCLnTab)

		checkCallCount(t, 1)
	})

	exeWithDynamicSymbols := buildExeWithDynamicSymbols(t, t.TempDir())

	t.Run("Upload dynamic symbols when enabled", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		uploader, err := newTestUploader(false, false)
		require.NoError(t, err)
		uploader.Start(ctx)
		uploader.UploadSymbols(libpf.FileID{}, exeWithDynamicSymbols, "build_id", &DummyOpener{})
		uploader.Stop()

		assert.Equal(t, 0, httpmock.GetTotalCallCount())
	})

	t.Run("Upload dynamic symbols when enabled", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		uploader, err := newTestUploader(true, false)
		require.NoError(t, err)
		uploader.Start(ctx)
		uploader.UploadSymbols(libpf.FileID{}, exeWithDynamicSymbols, "build_id", &DummyOpener{})
		req1 := <-c1
		req2 := <-c2
		checkRequest(t, req1, symbol.SourceDynamicSymbolTable)
		checkRequest(t, req2, symbol.SourceDynamicSymbolTable)

		checkCallCount(t, 1)
	})
}
