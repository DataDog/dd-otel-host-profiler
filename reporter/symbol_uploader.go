// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/zstd"
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/readatbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/process"
)

const uploadCacheSize = 16384
const uploadQueueSize = 1000
const uploadWorkerCount = 10

const sourceMapEndpoint = "/api/v2/srcmap"

const symbolCopyTimeout = 10 * time.Second
const uploadTimeout = 15 * time.Second

const buildIDSectionName = ".note.gnu.build-id"

var debugStrSectionNames = []string{".debug_str", ".zdebug_str", ".debug_str.dwo"}
var debugInfoSectionNames = []string{".debug_info", ".zdebug_info"}
var globalDebugDirectories = []string{"/usr/lib/debug"}

type uploadData struct {
	filePath string
	fileID   libpf.FileID
	buildID  string
	opener   process.FileOpener
}

type DatadogSymbolUploader struct {
	ddAPIKey             string
	ddAPPKey             string
	intakeURL            string
	version              string
	dryRun               bool
	uploadDynamicSymbols bool
	workerCount          int

	uploadCache   *lru.SyncedLRU[libpf.FileID, struct{}]
	client        *http.Client
	uploadQueue   chan uploadData
	symbolQuerier *DatadogSymbolQuerier
}

func NewDatadogSymbolUploader(version string) (*DatadogSymbolUploader, error) {
	err := exec.Command("objcopy", "--version").Run()
	if err != nil {
		return nil, fmt.Errorf("objcopy is not available: %w", err)
	}

	ddAPIKey := os.Getenv("DD_API_KEY")
	if ddAPIKey == "" {
		return nil, errors.New("DD_API_KEY is not set")
	}

	ddAPPKey := os.Getenv("DD_APP_KEY")
	if ddAPPKey == "" {
		return nil, errors.New("DD_APP_KEY is not set")
	}

	ddSite := os.Getenv("DD_SITE")
	if ddSite == "" {
		return nil, errors.New("DD_SITE is not set")
	}

	intakeURL, err := url.JoinPath("https://sourcemap-intake."+ddSite, sourceMapEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	dryRun, _ := strconv.ParseBool(os.Getenv("DD_EXPERIMENTAL_LOCAL_SYMBOL_UPLOAD_DRY_RUN"))

	uploadDynamicSymbols := true
	b, err := strconv.ParseBool(os.Getenv("DD_EXPERIMENTAL_LOCAL_SYMBOL_UPLOAD_DYNAMIC_SYMBOLS"))
	if err == nil {
		uploadDynamicSymbols = b
	}

	uploadCache, err := lru.NewSynced[libpf.FileID, struct{}](uploadCacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	symbolQuerier, err := NewDatadogSymbolQuerier(ddSite, ddAPIKey, ddAPPKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Datadog symbol querier: %w", err)
	}

	return &DatadogSymbolUploader{
		ddAPIKey:             ddAPIKey,
		ddAPPKey:             ddAPPKey,
		intakeURL:            intakeURL,
		version:              version,
		dryRun:               dryRun,
		uploadDynamicSymbols: uploadDynamicSymbols,
		workerCount:          uploadWorkerCount,
		client:               &http.Client{Timeout: uploadTimeout},
		uploadCache:          uploadCache,
		uploadQueue:          make(chan uploadData, uploadQueueSize),
		symbolQuerier:        symbolQuerier,
	}, nil
}

func (d *DatadogSymbolUploader) UploadSymbols(fileID libpf.FileID, filePath, buildID string,
	opener process.FileOpener) {
	_, ok := d.uploadCache.Get(fileID)
	if ok {
		log.Debugf("Skipping symbol upload for executable %s: already uploaded",
			filePath)
		return
	}

	// For short-lived processes, executable file might disappear from under our feet by the time we
	// try to upload symbols. It would be better to open the file here and enqueue the opened file.
	// We still need the file to exist later when we extract the debug symbols with objcopy though.
	// The alternative would be to dump the file to a temporary file through the opened reader and use
	// objcopy on that temporary file. The downside would be more disk I/O and more disk space used, and
	// do not seem to be worth it.
	// We can revisit this choice later if we switch to a different symbol extraction method.
	select {
	case d.uploadQueue <- uploadData{filePath, fileID, buildID, opener}:
		// Record immediately to avoid duplicate uploads
		d.uploadCache.Add(fileID, struct{}{})
	default:
		log.Warnf("Symbol upload queue is full, skipping symbol upload for file %q with file ID %q and build ID %q",
			filePath, fileID.StringNoQuotes(), buildID)
	}
}

func (d *DatadogSymbolUploader) GetExistingSymbolsOnBackend(ctx context.Context,
	e *executableMetadata) (SymbolSource, error) {
	buildIDs := []string{e.FileHash}
	if e.GNUBuildID != "" {
		buildIDs = append(buildIDs, e.GNUBuildID)
	}
	if e.GoBuildID != "" {
		buildIDs = append(buildIDs, e.GoBuildID)
	}

	symbolFiles, err := d.symbolQuerier.QuerySymbols(ctx, buildIDs, e.Arch)
	if err != nil {
		return None, fmt.Errorf("failed to query symbols: %w", err)
	}
	symbolSource := None
	for _, symbolFile := range symbolFiles {
		src, err := NewSymbolSource(symbolFile.SymbolSource)
		if err != nil {
			return None, fmt.Errorf("failed to parse symbol source: %w", err)
		}
		if src > symbolSource {
			symbolSource = src
		}
	}

	log.Debugf("Existing symbols for executable %s with build: %v", e, symbolSource)
	return symbolSource, nil
}

// Returns true if the upload was successful, false otherwise
func (d *DatadogSymbolUploader) upload(ctx context.Context, uploadData uploadData) bool {
	filePath := uploadData.filePath
	fileID := uploadData.fileID

	elfWrapper, err := openELF(filePath, uploadData.opener)
	// If the ELF file is not found, we ignore it
	// This can happen for short-lived processes that are already gone by the time
	// we try to upload symbols
	if err != nil {
		log.Debugf("Skipping symbol upload for executable %s: %v",
			uploadData.filePath, err)
		return false
	}
	defer elfWrapper.Close()

	debugElf, symbolSource := elfWrapper.findSymbols()
	if debugElf == nil {
		log.Debugf("Skipping symbol upload for executable %s: no debug symbols found", filePath)
		return false
	}
	if debugElf != elfWrapper {
		defer debugElf.Close()
	}
	if symbolSource == DynamicSymbolTable && !d.uploadDynamicSymbols {
		log.Debugf("Skipping symbol upload for executable %s: dynamic symbol table upload not allowed", filePath)
		return false
	}

	e := newExecutableMetadata(filePath, elfWrapper.elfFile, fileID, symbolSource, d.version)

	existingSymbolSource, err := d.GetExistingSymbolsOnBackend(ctx, e)
	if err != nil {
		log.Debugf("Failed to get existing symbols for executable %s: %v", filePath, err)
		return false
	}

	if existingSymbolSource >= symbolSource {
		log.Infof("Skipping symbol upload for executable %s: existing symbols with source %v", filePath,
			existingSymbolSource.String())
		return true
	}

	symbolPath := debugElf.actualFilePath

	if d.dryRun {
		log.Infof("Dry run: would upload symbols %s for executable: %s", debugElf.filePath, e)
		return true
	}

	err = d.handleSymbols(ctx, symbolPath, e)
	if err != nil {
		log.Errorf("Failed to handle symbols: %v for executable: %s", err, e)
		return false
	}

	log.Infof("Symbols uploaded successfully for executable: %s", e)
	return true
}

func (d *DatadogSymbolUploader) Run(ctx context.Context) {
	var wg sync.WaitGroup

	for range d.workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case uploadData := <-d.uploadQueue:
					if !d.upload(ctx, uploadData) {
						// Remove from cache to retry later
						d.uploadCache.Remove(uploadData.fileID)
					}
				}
			}
		}()
	}

	wg.Wait()
}

type executableMetadata struct {
	Arch          string `json:"arch"`
	GNUBuildID    string `json:"gnu_build_id"`
	GoBuildID     string `json:"go_build_id"`
	FileHash      string `json:"file_hash"`
	Type          string `json:"type"`
	SymbolSource  string `json:"symbol_source"`
	Origin        string `json:"origin"`
	OriginVersion string `json:"origin_version"`
	FileName      string `json:"filename"`

	filePath string
}

func newExecutableMetadata(fileName string, elfFile *pfelf.File, fileID libpf.FileID,
	symbolSource SymbolSource, profilerVersion string) *executableMetadata {
	isGolang := elfFile.IsGolang()

	buildID, err := elfFile.GetBuildID()
	if err != nil {
		log.Debugf(
			"Unable to get GNU build ID for executable %s: %s", fileName, err)
	}

	goBuildID := ""
	if isGolang {
		goBuildID, err = elfFile.GetGoBuildID()
		if err != nil {
			log.Debugf(
				"Unable to get Go build ID for executable %s: %s", fileName, err)
		}
	}

	return &executableMetadata{
		Arch:          runtime.GOARCH,
		GNUBuildID:    buildID,
		GoBuildID:     goBuildID,
		FileHash:      fileID.StringNoQuotes(),
		Type:          "elf_symbol_file",
		Origin:        "dd-otel-host-profiler",
		OriginVersion: profilerVersion,
		SymbolSource:  symbolSource.String(),
		FileName:      filepath.Base(fileName),
		filePath:      fileName,
	}
}

func (e *executableMetadata) String() string {
	return fmt.Sprintf(
		"%s, filename=%s, arch=%s, gnu_build_id=%s, go_build_id=%s, file_hash=%s, type=%s"+
			", symbol_source=%s, origin=%s, origin_version=%s",
		e.filePath, e.FileName, e.Arch, e.GNUBuildID, e.GoBuildID, e.FileHash, e.Type,
		e.SymbolSource, e.Origin, e.OriginVersion,
	)
}

func (d *DatadogSymbolUploader) handleSymbols(ctx context.Context, symbolPath string,
	e *executableMetadata) error {
	symbolFile, err := os.CreateTemp("", "objcopy-debug")
	if err != nil {
		return fmt.Errorf("failed to create temp file to extract symbols: %w", err)
	}
	defer os.Remove(symbolFile.Name())
	defer symbolFile.Close()

	ctx, cancel := context.WithTimeout(ctx, symbolCopyTimeout)
	defer cancel()
	err = d.copySymbols(ctx, symbolPath, symbolFile.Name())
	if err != nil {
		return fmt.Errorf("failed to copy symbols: %w", err)
	}

	err = d.uploadSymbols(ctx, symbolFile, e)
	if err != nil {
		return fmt.Errorf("failed to upload symbols: %w", err)
	}

	return nil
}

func (d *DatadogSymbolUploader) copySymbols(ctx context.Context, inputPath, outputPath string) error {
	args := []string{
		"--only-keep-debug",
		"--remove-section=.gdb_index",
		inputPath,
		outputPath,
	}
	_, err := exec.CommandContext(ctx, "objcopy", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to extract debug symbols: %w", cleanCmdError(err))
	}
	return nil
}

func (d *DatadogSymbolUploader) uploadSymbols(ctx context.Context, symbolFile *os.File,
	e *executableMetadata) error {
	req, err := d.buildSymbolUploadRequest(symbolFile, e)
	if err != nil {
		return fmt.Errorf("failed to build symbol upload request: %w", err)
	}

	req = req.WithContext(ctx)
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("error while uploading symbols: %s, %s", resp.Status, string(respBody))
	}

	return nil
}

func (d *DatadogSymbolUploader) buildSymbolUploadRequest(symbolFile *os.File,
	e *executableMetadata) (*http.Request, error) {
	b := new(bytes.Buffer)

	compressed := zstd.NewWriter(b)

	mw := multipart.NewWriter(compressed)

	// Copy the symbol file into the multipart writer
	filePart, err := mw.CreateFormFile("elf_symbol_file", "elf_symbol_file")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = io.Copy(filePart, symbolFile)
	if err != nil {
		return nil, fmt.Errorf("failed to copy symbol file: %w", err)
	}

	// Write the event metadata into the multipart writer
	eventPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="event"; filename="event.json"`},
		"Content-Type":        []string{"application/json"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create event part: %w", err)
	}

	err = json.NewEncoder(eventPart).Encode(e)
	if err != nil {
		return nil, fmt.Errorf("failed to write JSON metadata: %w", err)
	}

	// Close the multipart writer then the zstd writer
	err = mw.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	err = compressed.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close zstd writer: %w", err)
	}

	r, err := http.NewRequest(http.MethodPost, d.intakeURL, b)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	r.Header.Set("Dd-Api-Key", d.ddAPIKey)
	r.Header.Set("Dd-Evp-Origin", profilerName)
	r.Header.Set("Dd-Evp-Origin-Version", d.version)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Content-Encoding", "zstd")
	return r, nil
}

// cleanCmdError simplifies error messages from os/exec.Cmd.Run.
// For ExitErrors, it trims and returns stderr. By default, ExitError prints the exit
// status but not stderr.
//
// cleanCmdError returns other errors unmodified.
func cleanCmdError(err error) error {
	var xerr *exec.ExitError
	if errors.As(err, &xerr) {
		if stderr := strings.TrimSpace(string(xerr.Stderr)); stderr != "" {
			return fmt.Errorf("%w: %s", err, stderr)
		}
	}
	return err
}

// HasDWARFData is a copy of pfelf.HasDWARFData, but for the libpf.File interface.
func HasDWARFData(f *pfelf.File) bool {
	hasBuildID := false
	hasDebugStr := false
	for _, section := range f.Sections {
		// NOBITS indicates that the section is actually empty, regardless of the size in the
		// section header.
		if section.Type == elf.SHT_NOBITS {
			continue
		}

		if section.Name == buildIDSectionName {
			hasBuildID = true
		}

		if slices.Contains(debugStrSectionNames, section.Name) {
			hasDebugStr = section.Size > 0
		}

		// Some files have suspicious near-empty, partially stripped sections; consider them as not
		// having DWARF data.
		// The simplest binary gcc 10 can generate ("return 0") has >= 48 bytes for each section.
		// Let's not worry about executables that may not verify this, as they would not be of
		// interest to us.
		if section.Size < 32 {
			continue
		}

		if slices.Contains(debugInfoSectionNames, section.Name) {
			return true
		}
	}

	// Some alternate debug files only have a .debug_str section. For these we want to return true.
	// Use the absence of program headers and presence of a Build ID as heuristic to identify
	// alternate debug files.
	return len(f.Progs) == 0 && hasBuildID && hasDebugStr
}

type elfWrapper struct {
	reader         process.ReadAtCloser
	elfFile        *pfelf.File
	filePath       string
	actualFilePath string
	opener         process.FileOpener
}

func (e *elfWrapper) Close() {
	e.reader.Close()
}

func (e *elfWrapper) openELF(filePath string) (*elfWrapper, error) {
	return openELF(filePath, e.opener)
}

func openELF(filePath string, opener process.FileOpener) (*elfWrapper, error) {
	r, actualFilePath, err := opener.Open(filePath)
	if err != nil {
		return nil, err
	}
	// Wrap it in a cacher as we often do short reads
	buffered, err := readatbuf.New(r, 1024, 4)
	if err != nil {
		return nil, err
	}
	ef, err := pfelf.NewFile(buffered, 0, false)
	if err != nil {
		r.Close()
		return nil, err
	}
	return &elfWrapper{reader: r, elfFile: ef, filePath: filePath, actualFilePath: actualFilePath, opener: opener}, nil
}

// findSymbols attempts to find a symbol source for the elf file, it returns an elfWrapper around the elf file
// with symbols if found, or nil if no symbols were found.
func (e *elfWrapper) findSymbols() (*elfWrapper, SymbolSource) {
	if HasDWARFData(e.elfFile) {
		return e, DebugInfo
	}

	log.Debugf("No debug symbols found in %s", e.filePath)

	// Check if there is a separate debug ELF file for this executable
	// following the same order as GDB
	// https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html

	// First, check based on the GNU build ID
	debugElf := e.findDebugSymbolsWithBuildID()
	if debugElf != nil {
		if HasDWARFData(debugElf.elfFile) {
			return debugElf, DebugInfo
		}
		debugElf.Close()
		log.Debugf("No debug symbols found in buildID link file %s", debugElf.filePath)
	}

	// Then, check based on the debug link
	debugElf = e.findDebugSymbolsWithDebugLink()
	if debugElf != nil {
		if HasDWARFData(debugElf.elfFile) {
			return debugElf, DebugInfo
		}
		log.Debugf("No debug symbols found in debug link file %s", debugElf.filePath)
		debugElf.Close()
	}

	// Check if initial elf file has a symbol table
	if e.elfFile.Section(".symtab") != nil {
		return e, SymbolTable
	}

	// Check if initial elf file has a dynamic symbol table
	if e.elfFile.Section(".dynsym") != nil {
		return e, DynamicSymbolTable
	}

	return nil, None
}

func (e *elfWrapper) findDebugSymbolsWithBuildID() *elfWrapper {
	buildID, err := e.elfFile.GetBuildID()
	if err != nil || len(buildID) < 2 {
		log.Debugf("Failed to get build ID for %s: %v", e.filePath, err)
		return nil
	}

	// Try to find the debug file
	debugDirectories := make([]string, 0, len(globalDebugDirectories))
	for _, dir := range globalDebugDirectories {
		debugDirectories = append(debugDirectories, filepath.Join(dir, ".build-id"))
	}

	for _, debugPath := range debugDirectories {
		debugFile := filepath.Join(debugPath, buildID[:2], buildID[2:]+".debug")
		debugELF, err := e.openELF(debugFile)
		if err != nil {
			continue
		}
		debugBuildID, err := debugELF.elfFile.GetBuildID()
		if err != nil || buildID != debugBuildID {
			debugELF.Close()
			continue
		}
		return debugELF
	}
	return nil
}

func (e *elfWrapper) findDebugSymbolsWithDebugLink() *elfWrapper {
	linkName, linkCRC32, err := e.elfFile.GetDebugLink()
	if err != nil {
		return nil
	}

	// Try to find the debug file
	executablePath := filepath.Dir(e.filePath)

	debugDirectories := []string{
		executablePath,
		filepath.Join(executablePath, ".debug"),
	}
	for _, dir := range globalDebugDirectories {
		debugDirectories = append(debugDirectories,
			filepath.Join(dir, executablePath))
	}

	for _, debugPath := range debugDirectories {
		debugFile := filepath.Join(debugPath, executablePath, linkName)
		debugELF, err := e.openELF(debugFile)
		if err != nil {
			continue
		}
		if debugELF.elfFile.Section(".debug_frame") == nil {
			debugELF.Close()
			continue
		}
		fileCRC32, err := debugELF.elfFile.CRC32()
		if err != nil || fileCRC32 != linkCRC32 {
			debugELF.Close()
			continue
		}
		return debugELF
	}
	return nil
}
