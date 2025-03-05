// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"context"
	"debug/elf"
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
	"time"

	"github.com/DataDog/zstd"
	"github.com/jarcoal/httpmock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
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

func checkGoPCLnTab(t *testing.T, filename string, checkGoFunc bool) {
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
	checkGoPCLnTab(t, outputFile, true)
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

func newTestUploader() (*DatadogSymbolUploader, error) {
	cfg := &SymbolUploaderConfig{
		Enabled:              true,
		UploadDynamicSymbols: true,
		SymbolQueryInterval:  0,
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

type DummyOpener struct{}

func (o *DummyOpener) Open(path string) (reader process.ReadAtCloser, actualPath string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	return f, fmt.Sprintf("/proc/%v/fd/%v", os.Getpid(), f.Fd()), nil
}

func checkRequest(t *testing.T, req *http.Request) {
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

	elfFile, err := elf.NewFile(f)
	require.NoError(t, err)
	defer elfFile.Close()

	require.NoError(t, err)
	require.NotNil(t, findDynamicSymbol(elfFile, "foo"), "failed to find symbol foo")
}

func TestDynamicSymbolExtraction(t *testing.T) {
	t.Parallel()
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	c := make(chan *http.Request, 1)

	log.SetLevel(log.DebugLevel)
	httpmock.RegisterResponder("POST", buildSymbolQueryURL("foobar.com"),
		httpmock.NewStringResponder(200, `{"data": []}`))
	httpmock.RegisterResponder("POST", buildSourcemapIntakeURL("foobar.com"),
		func(req *http.Request) (*http.Response, error) {
			fmt.Printf("Received request\n")
			c <- req
			return httpmock.NewStringResponse(200, ""), nil
		})

	srcFile := "../testdata/foo.c"
	tmpDir := t.TempDir()
	exe := filepath.Join(tmpDir, "libfoo.so")
	cmd := exec.Command("gcc", "-Wl,--strip-all", "-shared", "-o", exe, srcFile)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.Args, err, out)

	uploader, err := newTestUploader()
	require.NoError(t, err)
	go func() { uploader.Run(context.Background()) }()

	uploader.UploadSymbols(libpf.FileID{}, exe, "build_id", &DummyOpener{})

	select {
	case req := <-c:
		checkRequest(t, req)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for request")
	}
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
}
