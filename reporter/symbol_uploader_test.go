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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/zstd"
	"github.com/jarcoal/httpmock"
	"github.com/jonboulle/clockwork"
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
	err = CopySymbols(context.Background(), filename, outputFile, goPCLnTabInfo)
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
	if expectedSymbolSource == symbol.SourceGoPCLnTab {
		checkGoPCLnTab(t, elfFile, true)
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

func newTestUploader(uploadDynamicSymbols, uploadGoPCLnTab bool, batchingInterval time.Duration) (*DatadogSymbolUploader, error) {
	cfg := &SymbolUploaderConfig{
		Enabled:              true,
		UploadDynamicSymbols: uploadDynamicSymbols,
		UploadGoPCLnTab:      uploadGoPCLnTab,
		SymbolQueryInterval:  batchingInterval,
		SymbolEndpoints: []SymbolEndpoint{
			{
				Site:   "foobar.com",
				APIKey: "api_key",
				AppKey: "app_key",
			},
		},
	}
	return NewDatadogSymbolUploader(cfg)
}

type TestOpener struct{}

func (o *TestOpener) Open(path string) (reader process.ReadAtCloser, actualPath string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	return f, fmt.Sprintf("/proc/%v/fd/%v", os.Getpid(), f.Fd()), nil
}

func buildGoExe(t *testing.T, tmpDir string, debugInfo bool) string {
	f, err := os.CreateTemp(tmpDir, "helloworld")
	require.NoError(t, err)
	defer f.Close()

	exe := f.Name()
	args := []string{"build", "-o", exe}
	if !debugInfo {
		args = append(args, "-ldflags=-s -w")
	}
	args = append(args, "../testdata/helloworld.go")
	cmd := exec.Command("go", args...) // #nosec G204
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.Args, err, out)
	return exe
}

//nolint:tparallel
func TestSymbolUpload(t *testing.T) {
	t.Parallel()
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	symbolQueryURL := buildSymbolQueryURL("foobar.com")
	sourcemapIntakeURL := buildSourcemapIntakeURL("foobar.com")

	symbolUploadChannel := make(chan *http.Request)

	registerResponders := func(symbolQueryStatus int, sourcemapIntakeStatus int) {
		symbolUploadChannel = make(chan *http.Request)

		httpmock.RegisterResponder("POST", symbolQueryURL,
			httpmock.NewStringResponder(symbolQueryStatus, `{"data": []}`))
		httpmock.RegisterResponder("POST", sourcemapIntakeURL,
			func(req *http.Request) (*http.Response, error) {
				symbolUploadChannel <- req
				return httpmock.NewStringResponse(sourcemapIntakeStatus, ""), nil
			})
	}

	exe := buildGoExe(t, t.TempDir(), false)

	t.Run("No upload when no symbols", func(t *testing.T) {
		registerResponders(http.StatusOK, http.StatusOK)

		uploader, err := newTestUploader(false, false, 0)
		require.NoError(t, err)
		uploader.Start()

		uploader.UploadSymbols(libpf.FileID{}, exe, "build_id", &TestOpener{})
		uploader.Stop()

		assert.Equal(t, 0, httpmock.GetTotalCallCount())
	})

	t.Run("Upload debug_info when available", func(t *testing.T) {
		registerResponders(http.StatusOK, http.StatusOK)

		exeWithDebugInfo := buildGoExe(t, t.TempDir(), true)

		uploader, err := newTestUploader(false, false, 0)
		require.NoError(t, err)
		uploader.Start()
		defer uploader.Stop()
		uploader.UploadSymbols(libpf.FileID{}, exeWithDebugInfo, "build_id", &TestOpener{})
		req := waitForOrTimeout(t, symbolUploadChannel, 5*time.Second)
		checkRequest(t, req, symbol.SourceDebugInfo)
		info := httpmock.GetCallCountInfo()

		if info[fmt.Sprintf("POST %s", symbolQueryURL)] != 1 {
			t.Log(fmt.Sprint(info))
			t.Errorf("Failed to call symbol query endpoint")
		}

		if info[fmt.Sprintf("POST %s", sourcemapIntakeURL)] != 1 {
			t.Log(fmt.Sprint(info))
			t.Errorf("Failed to call symbol query endpoint")
		}
	})

	t.Run("Upload pclntab when enabled", func(t *testing.T) {
		registerResponders(http.StatusOK, http.StatusOK)

		uploader, err := newTestUploader(false, true, 0)
		require.NoError(t, err)
		uploader.Start()
		defer uploader.Stop()
		uploader.UploadSymbols(libpf.FileID{}, exe, "build_id", &TestOpener{})
		req := waitForOrTimeout(t, symbolUploadChannel, 5*time.Second)
		checkRequest(t, req, symbol.SourceGoPCLnTab)
		info := httpmock.GetCallCountInfo()

		if info[fmt.Sprintf("POST %s", symbolQueryURL)] != 1 {
			t.Log(fmt.Sprint(info))
			t.Errorf("Failed to call symbol query endpoint")
		}

		if info[fmt.Sprintf("POST %s", sourcemapIntakeURL)] != 1 {
			t.Log(fmt.Sprint(info))
			t.Errorf("Failed to call symbol query endpoint")
		}
	})

	t.Run("Re-upload executable if upload was unsuccessful", func(t *testing.T) {
		registerResponders(http.StatusOK, http.StatusInternalServerError)

		uploader, err := newTestUploader(false, true, 0)
		require.NoError(t, err)
		uploader.Start()
		defer uploader.Stop()
		uploader.UploadSymbols(libpf.FileID{}, exe, "build_id", &TestOpener{})
		req := waitForOrTimeout(t, symbolUploadChannel, 5*time.Second)
		checkRequest(t, req, symbol.SourceGoPCLnTab)
		uploader.UploadSymbols(libpf.FileID{}, exe, "build_id", &TestOpener{})
		req = waitForOrTimeout(t, symbolUploadChannel, 5*time.Second)
		checkRequest(t, req, symbol.SourceGoPCLnTab)

		info := httpmock.GetCallCountInfo()

		if info[fmt.Sprintf("POST %s", symbolQueryURL)] != 2 {
			t.Log(fmt.Sprint(info))
			t.Errorf("Failed to call symbol query endpoint")
		}

		if info[fmt.Sprintf("POST %s", sourcemapIntakeURL)] != 2 {
			t.Log(fmt.Sprint(info))
			t.Errorf("Failed to call symbol query endpoint")
		}
	})

	t.Run("Batch symbol requests", func(t *testing.T) {
		symbolRequestChannel := make(chan *http.Request)

		httpmock.RegisterResponder(http.MethodPost, symbolQueryURL, func(req *http.Request) (*http.Response, error) {
			symbolRequestChannel <- req
			return httpmock.NewStringResponse(http.StatusNotFound, `{"data\": []}`), nil
		})

		batchingInterval := time.Nanosecond
		uploader, err := newTestUploader(false, true, batchingInterval)
		require.NoError(t, err)

		fakeClock := clockwork.NewFakeClock()
		uploader.overrideClock(fakeClock)
		uploader.Start()
		defer uploader.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = fakeClock.BlockUntilContext(ctx, 1)
		assert.NoError(t, err)

		uploader.batchingQueue <- symbol.NewElfForTest("amd64", "build_id", "go_build_id", "file_hash")
		uploader.batchingQueue <- symbol.NewElfForTest("amd64", "build_id2", "go_build_id2", "file_hash2")
		uploader.batchingQueue <- symbol.NewElfForTest("amd64", "build_id3", "go_build_id3", "file_hash3")

		// Wait for the first batch to be collected
		time.Sleep(1 * time.Millisecond)

		err = fakeClock.BlockUntilContext(ctx, 1)
		assert.NoError(t, err)
		fakeClock.Advance(batchingInterval)

		waitForOrTimeout(t, symbolRequestChannel, 5*time.Second)

		info := httpmock.GetCallCountInfo()

		if info[fmt.Sprintf("POST %s", symbolQueryURL)] != 1 {
			t.Log(fmt.Sprint(info))
			t.Errorf("Expected one call for symbol query endpoint")
		}
	})

	t.Run("Send batches when maxBatchSize is hit", func(t *testing.T) {
		symbolRequestChannel := make(chan *http.Request)

		httpmock.RegisterResponder(http.MethodPost, symbolQueryURL, func(req *http.Request) (*http.Response, error) {
			symbolRequestChannel <- req
			return httpmock.NewStringResponse(http.StatusNotFound, `{"data\": []}`), nil
		})

		uploader, err := newTestUploader(false, true, time.Minute)
		require.NoError(t, err)
		uploader.Start()

		numBatches := 2

		for i := range numBatches * uploader.batchingMaxSize {
			index := strconv.Itoa(i)
			uploader.batchingQueue <- symbol.NewElfForTest(
				"amd64",
				"build_id"+index,
				"go_build_id"+index,
				"file_hash"+index,
			)
		}

		waitForOrTimeout(t, symbolRequestChannel, 5*time.Second)
		waitForOrTimeout(t, symbolRequestChannel, 5*time.Second)

		uploader.Stop()

		info := httpmock.GetCallCountInfo()

		if info[fmt.Sprintf("POST %s", symbolQueryURL)] != numBatches {
			t.Log(fmt.Sprint(info))
			t.Errorf("Expected one call for symbol query endpoint")
		}
	})
}

func waitForOrTimeout[T any](t *testing.T, ch <-chan T, timeout time.Duration) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(timeout):
		t.Fail()
		panic("panic waiting for timeout")
	}
}
