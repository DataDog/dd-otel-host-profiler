// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/jsonapi"
	"github.com/DataDog/zstd"
	"github.com/jarcoal/httpmock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
	"github.com/DataDog/dd-otel-host-profiler/reporter/symbol"
)

var objcopyZstdSupport = CheckObjcopyZstdSupport()

// dummyProcess implements pfelf.Process for testing purposes
type dummyProcess struct {
	pid libpf.PID
}

func (d *dummyProcess) PID() libpf.PID {
	return d.pid
}

func (d *dummyProcess) GetMachineData() process.MachineData {
	return process.MachineData{}
}

func (d *dummyProcess) GetMappings() ([]process.Mapping, uint32, error) {
	return nil, 0, errors.New("not implemented")
}

func (d *dummyProcess) GetThreads() ([]process.ThreadInfo, error) {
	return nil, errors.New("not implemented")
}

func (d *dummyProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}

func (d *dummyProcess) GetMappingFileLastModified(_ *process.Mapping) int64 {
	return 0
}

func (d *dummyProcess) CalculateMappingFileID(m *process.Mapping) (libpf.FileID, error) {
	return libpf.FileIDFromExecutableFile(m.Path.String())
}

func (d *dummyProcess) OpenMappingFile(m *process.Mapping) (process.ReadAtCloser, error) {
	return os.Open(m.Path.String())
}

func (d *dummyProcess) OpenELF(name string) (*pfelf.File, error) {
	return pfelf.Open(name)
}

func (d *dummyProcess) ExtractAsFile(name string) (string, error) {
	return path.Join("/proc", strconv.Itoa(int(d.pid)), "root", name), nil
}

func (d *dummyProcess) Close() error {
	return nil
}

func newExecutableMetadata(t *testing.T, filePath, goBuildID string) *reporter.ExecutableMetadata {
	fileID, err := libpf.FileIDFromExecutableFile(filePath)
	require.NoError(t, err)
	mf := libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
		FileID:     fileID,
		FileName:   libpf.Intern(path.Base(filePath)),
		GnuBuildID: "",
		GoBuildID:  goBuildID,
	})
	pr := &dummyProcess{pid: libpf.PID(os.Getpid())}
	m := &process.Mapping{
		Path: libpf.Intern(filePath),
	}
	return &reporter.ExecutableMetadata{
		MappingFile:       mf,
		Process:           pr,
		Mapping:           m,
		DebuglinkFileName: "",
	}
}

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
	err = CopySymbols(t.Context(), filename, outputFile, goPCLnTabInfo, nil, false)
	require.NoError(t, err)
	f, err := elf.Open(outputFile)
	require.NoError(t, err)
	defer f.Close()
	checkGoPCLnTab(t, f, true)
}

func checkRequest(t *testing.T, req *http.Request, expectedSymbolSource symbol.Source, expectedGoPCLnTab bool, expectedContentEncoding string) {
	require.Equal(t, "POST", req.Method)
	if expectedContentEncoding != "" {
		require.Equal(t, expectedContentEncoding, req.Header.Get("Content-Encoding"))
	} else {
		require.NotContains(t, req.Header, "Content-Encoding")
	}

	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	require.NoError(t, err)
	boundary, ok := params["boundary"]
	require.True(t, ok)

	var reader io.ReadCloser
	if req.Header.Get("Content-Encoding") == "zstd" {
		reader = zstd.NewReader(req.Body)
		defer reader.Close()
	} else {
		reader = req.Body
	}

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

	if expectedGoPCLnTab || expectedSymbolSource == symbol.SourceGoPCLnTab {
		checkGoPCLnTab(t, elfFile, true)
	}

	switch expectedSymbolSource {
	case symbol.SourceDynamicSymbolTable:
		require.NotNil(t, findDynamicSymbol(elfFile, "_cgo_panic"))
	case symbol.SourceSymbolTable:
		require.NotNil(t, findSymbol(elfFile, "main.main"))
	case symbol.SourceDebugInfo:
		require.True(t, pfelf.HasDWARFData(elfFile))
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

var testEndpoints = []string{"a.com", "b.com", "c.com", "d.com", "e.com"}

type uploaderOpts struct {
	uploadDynamicSymbols           bool
	uploadGoPCLnTab                bool
	disableDebugSectionCompression bool
}

func newTestUploader(opts uploaderOpts) (*DatadogSymbolUploader, error) {
	endpoints := make([]SymbolEndpoint, 0, len(testEndpoints))
	for _, e := range testEndpoints {
		endpoints = append(endpoints, SymbolEndpoint{
			Site:   e,
			APIKey: "api_key",
			AppKey: "app_key",
		})
	}

	cfg := &SymbolUploaderConfig{
		Enabled:                        true,
		UploadDynamicSymbols:           opts.uploadDynamicSymbols,
		UploadGoPCLnTab:                opts.uploadGoPCLnTab,
		SymbolQueryInterval:            0,
		SymbolEndpoints:                endpoints,
		DisableDebugSectionCompression: opts.disableDebugSectionCompression,
	}
	return NewDatadogSymbolUploader(cfg)
}

type buildOptions struct {
	dynsym           bool
	symtab           bool
	debugInfos       bool
	corruptGoPCLnTab bool
}

func buildGo(t *testing.T, tmpDir, buildID string, opts buildOptions) string {
	f, err := os.CreateTemp(tmpDir, "helloworld")
	require.NoError(t, err)
	defer f.Close()

	exe := f.Name()
	args := []string{"build", "-o", exe}
	ldflags := "-ldflags=-buildid=" + buildID + " "
	if opts.dynsym {
		ldflags += "-linkmode=external "
	}

	args = append(args, ldflags, "../testdata/helloworld.go")
	cmd := exec.Command("go", args...) // #nosec G204
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test binary with `%v`: %s\n%s", cmd.Args, err, out)

	args = []string{"-R", ".note.gnu.build-id"}
	if opts.debugInfos && !opts.symtab {
		t.Errorf("Cannot have debug infos without symtab")
	}

	if !opts.debugInfos {
		if opts.symtab {
			args = append(args, "-g")
		} else {
			args = append(args, "-S")
		}
	}
	if opts.corruptGoPCLnTab {
		// Remove the pclntab section
		args = append(args, "-R", ".gopclntab")
	}
	args = append(args, exe)
	cmd = exec.Command("objcopy", args...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "failed to strip test binary with `%v`: %s\n%s", cmd.Args, err, out)

	return exe
}

func buildSymbolQueryResponse(t *testing.T, buildID string, symbolSource symbol.Source) string {
	var symbolFiles []SymbolFile
	if symbolSource != symbol.SourceNone {
		symbolFiles = []SymbolFile{
			{
				ID:           "1",
				BuildID:      buildID,
				SymbolSource: symbolSource.String(),
				BuildIDType:  "go_build_id",
			},
		}
	}
	r, err := jsonapi.Marshal(&symbolFiles)
	require.NoError(t, err)
	return string(r)
}

func registerResponders(t *testing.T, buildID string) []chan *http.Request {
	channels := make([]chan *http.Request, 0, len(testEndpoints))
	symbolSources := []symbol.Source{symbol.SourceNone, symbol.SourceDynamicSymbolTable, symbol.SourceSymbolTable, symbol.SourceGoPCLnTab, symbol.SourceDebugInfo}
	for i, e := range testEndpoints {
		c := make(chan *http.Request, 1)
		channels = append(channels, c)
		httpmock.RegisterResponder("POST", buildSymbolQueryURL(e),
			httpmock.NewStringResponder(200, buildSymbolQueryResponse(t, buildID, symbolSources[i])))
		httpmock.RegisterResponder("POST", buildSourcemapIntakeURL(e),
			func(req *http.Request) (*http.Response, error) {
				// Read request body before sending response otherwise client will receive the response before having sent all the data
				b, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				req.Body = io.NopCloser(bytes.NewReader(b))
				c <- req
				return httpmock.NewStringResponse(200, ""), nil
			})
	}
	return channels
}

//nolint:tparallel
func TestSymbolUpload(t *testing.T) {
	t.Parallel()
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	log.SetLevel(log.DebugLevel)
	buildID := "some_go_build_id"
	channels := registerResponders(t, buildID)

	checkUploadsWithEncoding := func(t *testing.T, expectedSymbolSource symbol.Source, expectedGoPCLnTab bool, expectedUploads []bool, expectedEncoding string) {
		callCountInfo := httpmock.GetCallCountInfo()
		for i, e := range testEndpoints {
			assert.Equal(t, 1, callCountInfo["POST "+buildSymbolQueryURL(e)])
			if expectedUploads[i] {
				assert.Equal(t, 1, callCountInfo["POST "+buildSourcemapIntakeURL(e)])
				req := <-channels[i]
				checkRequest(t, req, expectedSymbolSource, expectedGoPCLnTab, expectedEncoding)
			} else {
				assert.Equal(t, 0, callCountInfo["POST "+buildSourcemapIntakeURL(e)])
			}
		}
	}

	checkUploads := func(t *testing.T, expectedSymbolSource symbol.Source, expectedGoPCLnTab bool, expectedUploads []bool) {
		expectedEncoding := ""
		if !objcopyZstdSupport {
			expectedEncoding = "zstd"
		}
		checkUploadsWithEncoding(t, expectedSymbolSource, expectedGoPCLnTab, expectedUploads, expectedEncoding)
	}

	goExeNoSymbols := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: false, symtab: false, debugInfos: false})
	goExeyDynsym := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: false, debugInfos: false})
	goExeSymtab := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: true, debugInfos: false})
	goExeDebugInfos := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: true, debugInfos: true})
	goExeyDynsymCorruptGoPCLnTab := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: false, debugInfos: false, corruptGoPCLnTab: true})
	goExeDebugInfosCorruptGoPCLnTab := buildGo(t, t.TempDir(), buildID, buildOptions{dynsym: true, symtab: true, debugInfos: true, corruptGoPCLnTab: true})

	t.Run("No symbol upload if no symbols", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeNoSymbols, buildID))
		uploader.Stop()

		assert.Equal(t, 0, httpmock.GetTotalCallCount())
	})

	t.Run("Upload if symtab", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeSymtab, buildID))
		uploader.Stop()

		checkUploads(t, symbol.SourceSymbolTable, false, []bool{true, true, false, false, false})
	})

	t.Run("Upload if debug info", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeDebugInfos, buildID))
		uploader.Stop()

		checkUploads(t, symbol.SourceDebugInfo, false, []bool{true, true, true, true, false})
	})

	t.Run("No upload if dynamic symbols", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsym, buildID))
		uploader.Stop()

		assert.Equal(t, 0, httpmock.GetTotalCallCount())
	})

	t.Run("Upload if dynamic symbols when enabled", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{uploadDynamicSymbols: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsym, buildID))
		uploader.Stop()

		checkUploads(t, symbol.SourceDynamicSymbolTable, false, []bool{true, false, false, false, false})
	})

	t.Run("Upload pclntab when enabled", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeNoSymbols, buildID))
		uploader.Stop()

		checkUploads(t, symbol.SourceGoPCLnTab, true, []bool{true, true, true, false, false})
	})

	t.Run("Upload debug infos if pclntab is corrupted", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeDebugInfosCorruptGoPCLnTab, buildID))
		uploader.Stop()

		checkUploads(t, symbol.SourceDebugInfo, false, []bool{true, true, true, true, false})
	})

	t.Run("Upload dynamic symbols if pclntab is corrupted and only dyn sym when enabled", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{uploadDynamicSymbols: true, uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsymCorruptGoPCLnTab, buildID))
		uploader.Stop()

		checkUploads(t, symbol.SourceDynamicSymbolTable, false, []bool{true, false, false, false, false})
	})

	t.Run("No symbol upload if pclntab is corrupted and only dynsym", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{uploadGoPCLnTab: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeyDynsymCorruptGoPCLnTab, buildID))
		uploader.Stop()

		checkUploads(t, symbol.SourceNone, false, []bool{false, false, false, false, false})
	})

	t.Run("Upload compressed request when debug section compression is disabled", func(t *testing.T) {
		httpmock.ZeroCallCounters()
		uploader, err := newTestUploader(uploaderOpts{disableDebugSectionCompression: true})
		require.NoError(t, err)
		uploader.Start(t.Context())

		uploader.UploadSymbols(newExecutableMetadata(t, goExeDebugInfos, buildID))
		uploader.Stop()

		checkUploadsWithEncoding(t, symbol.SourceDebugInfo, false, []bool{true, true, true, true, false}, "zstd")
	})
}

// Verify that the symbol uploader transport has the same exported fields as http.DefaultTransport
// when HTTP/2 is disabled
func TestTransport(t *testing.T) {
	cfg := &SymbolUploaderConfig{
		Enabled:         true,
		UseHTTP2:        false, // This forces creation of custom transport
		SymbolEndpoints: []SymbolEndpoint{{Site: "test.com", APIKey: "key", AppKey: "app"}},
		Version:         "test",
	}

	uploader, err := NewDatadogSymbolUploader(cfg)
	require.NoError(t, err)

	customTransport, ok := uploader.client.Transport.(*http.Transport)
	require.True(t, ok, "Expected custom transport to be *http.Transport")

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok, "Expected http.DefaultTransport to be *http.Transport")

	// Use reflection to compare all exported fields
	customValue := reflect.ValueOf(customTransport).Elem()
	defaultValue := reflect.ValueOf(defaultTransport).Elem()
	customType := customValue.Type()

	for i := range customType.NumField() {
		field := customType.Field(i)
		if !field.IsExported() {
			continue
		}

		customFieldValue := customValue.Field(i)
		defaultFieldValue := defaultValue.Field(i)

		// Special handling for intentionally different fields
		switch field.Name {
		case "TLSNextProto":
			// TLSNextProto should be an empty map in custom transport to disable HTTP/2
			assert.NotNil(t, customFieldValue.Interface(), "TLSNextProto should not be nil")
			assert.Equal(t, 0, customFieldValue.Len(), "TLSNextProto should be empty map")
		case "ForceAttemptHTTP2":
			// ForceAttemptHTTP2 should be false in custom transport to disable HTTP/2
			assert.False(t, customFieldValue.Bool(), "ForceAttemptHTTP2 should be false to disable HTTP/2")
		default:
			if customFieldValue.Kind() == reflect.Func {
				assert.Equal(t, defaultFieldValue.Pointer(), customFieldValue.Pointer(), "Function field %s should match", field.Name)
				continue
			}
			if !customFieldValue.CanInterface() || !defaultFieldValue.CanInterface() {
				assert.Failf(t, "Cannot compare field %s", field.Name)
				continue
			}
			assert.Equal(t, defaultFieldValue.Interface(), customFieldValue.Interface(),
				"Field %s should match default transport", field.Name)
		}
	}
}
