// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bytes"
	"context"
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
	"strings"
	"sync"
	"time"

	"github.com/DataDog/zstd"
	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
)

const (
	uploadCacheSize   = 16384
	uploadQueueSize   = 1000
	uploadWorkerCount = 10

	sourceMapEndpoint = "/api/v2/srcmap"

	symbolCopyTimeout = 10 * time.Second
	uploadTimeout     = 15 * time.Second

	buildIDSectionName = ".note.gnu.build-id"
)

type uploadData struct {
	filePath string
	fileID   libpf.FileID
	buildID  string
	opener   process.FileOpener
}

type DatadogSymbolUploader struct {
	symbolEndpoints      []SymbolEndpoint
	intakeURLs           []string
	version              string
	dryRun               bool
	uploadDynamicSymbols bool
	uploadGoPCLnTab      bool
	workerCount          int

	uploadCache    *lru.SyncedLRU[libpf.FileID, struct{}]
	client         *http.Client
	uploadQueue    chan uploadData
	symbolQueriers []DatadogSymbolQuerier
}

func NewDatadogSymbolUploader(cfg *SymbolUploaderConfig) (*DatadogSymbolUploader, error) {
	err := exec.Command("objcopy", "--version").Run()
	if err != nil {
		return nil, fmt.Errorf("objcopy is not available: %w", err)
	}

	if len(cfg.SymbolEndpoints) == 0 {
		return nil, errors.New("no endpoints to upload symbols to")
	}

	var intakeURLs = make([]string, len(cfg.SymbolEndpoints))
	var symbolQueriers = make([]DatadogSymbolQuerier, len(cfg.SymbolEndpoints))

	for i, endpoints := range cfg.SymbolEndpoints {
		var intakeURL string
		var symbolQuerier DatadogSymbolQuerier
		if intakeURL, err = url.JoinPath("https://sourcemap-intake."+endpoints.Site, sourceMapEndpoint); err != nil {
			return nil, fmt.Errorf("failed to parse URL: %w", err)
		}
		intakeURLs[i] = intakeURL

		if symbolQuerier, err = NewDatadogSymbolQuerier(endpoints.Site, endpoints.APIKey, endpoints.AppKey); err != nil {
			return nil, fmt.Errorf("failed to create Datadog symbol querier: %w", err)
		}
		if cfg.SymbolQueryInterval > 0 {
			symbolQuerier = NewBatchSymbolQuerier(BatchSymbolQuerierConfig{
				BatchInterval: cfg.SymbolQueryInterval,
				Querier:       symbolQuerier,
			})
		}

		symbolQueriers[i] = symbolQuerier
	}

	uploadCache, err := lru.NewSynced[libpf.FileID, struct{}](uploadCacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	return &DatadogSymbolUploader{
		symbolEndpoints:      cfg.SymbolEndpoints,
		intakeURLs:           intakeURLs,
		version:              cfg.Version,
		dryRun:               cfg.DryRun,
		uploadDynamicSymbols: cfg.UploadDynamicSymbols,
		uploadGoPCLnTab:      cfg.UploadGoPCLnTab,
		workerCount:          uploadWorkerCount,
		client:               &http.Client{Timeout: uploadTimeout},
		uploadCache:          uploadCache,
		uploadQueue:          make(chan uploadData, uploadQueueSize),
		symbolQueriers:       symbolQueriers,
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
	e *elfSymbols, sQind int) (SymbolSource, error) {
	buildIDs := []string{e.fileHash}
	if e.gnuBuildID != "" {
		buildIDs = append(buildIDs, e.gnuBuildID)
	}
	if e.goBuildID != "" {
		buildIDs = append(buildIDs, e.goBuildID)
	}

	symbolFiles, err := d.symbolQueriers[sQind].QuerySymbols(ctx, buildIDs, e.arch)
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

func (d *DatadogSymbolUploader) getSymbolSource(symbols *elfSymbols) SymbolSource {
	source := symbols.symbolSource()

	if source == DynamicSymbolTable && !d.uploadDynamicSymbols {
		source = None
	}

	return source
}

func (d *DatadogSymbolUploader) getSymbolsFromDisk(uploadData uploadData) *elfSymbols {
	filePath := uploadData.filePath
	fileID := uploadData.fileID

	symbols, err := newElfSymbols(filePath, fileID, uploadData.opener)
	if err != nil {
		log.Debugf("Skipping symbol upload for executable %s: %v",
			uploadData.filePath, err)
		return nil
	}

	return symbols
}

// Returns true if the upload was successful, false otherwise
func (d *DatadogSymbolUploader) upload(ctx context.Context, symbols *elfSymbols, ind int) bool {
	existingSymbolSource, err := d.GetExistingSymbolsOnBackend(ctx, symbols, ind)
	if err != nil {
		log.Warnf("Failed to get existing symbols for executable %s: %v", symbols.fileHash, err)
		return false
	}

	symbolSource := d.getSymbolSource(symbols)
	if symbols.isGolang && d.uploadGoPCLnTab {
		symbolSource = max(symbolSource, GoPCLnTab)
	}

	if symbolSource == None {
		log.Debugf("Skipping symbol upload for executable %s: no debug symbols found", symbols.filePath)
		return false
	}

	if existingSymbolSource >= symbolSource {
		log.Infof("Skipping symbol upload for executable %s: existing symbols with source %v", symbols.filePath,
			existingSymbolSource.String())
		return true
	}

	if symbols.isGolang && d.uploadGoPCLnTab {
		if symbols.getGoPCLnTab() == nil {
			symbolSource = d.getSymbolSource(symbols)
			if symbolSource == None {
				log.Debugf("Skipping symbol upload for executable %s: no debug symbols found", symbols.filePath)
				return false
			}
			if existingSymbolSource >= symbolSource {
				log.Infof("Skipping symbol upload for executable %s: existing symbols with source %v", symbols.filePath,
					existingSymbolSource.String())
				return true
			}
		}
	}

	if d.dryRun {
		log.Infof("Dry run: would upload symbols for executable: %s", symbols)
		return true
	}

	err = d.handleSymbols(ctx, symbols, ind)
	if err != nil {
		log.Errorf("Failed to handle symbols: %v for executable: %s", err, symbols)
		return false
	}

	log.Infof("Symbols uploaded successfully for executable: %s", symbols)
	return true
}

func (d *DatadogSymbolUploader) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, querier := range d.symbolQueriers {
		querier.Start(ctx)
	}

	for range d.workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case uploadData := <-d.uploadQueue:
					symbols := d.getSymbolsFromDisk(uploadData)
					if symbols == nil {
						d.uploadCache.Remove(uploadData.fileID)
						break
					}
					// TODO: upload symbols to endpoints concurrently (beware of gopclntab extraction that is not thread-safe)
					for i := range d.intakeURLs {
						if !d.upload(ctx, symbols, i) {
							// Remove from cache to retry later
							d.uploadCache.Remove(uploadData.fileID)
						}
					}
					symbols.close()
				}
			}
		}()
	}

	wg.Wait()
}

type symbolUploadRequestMetadata struct {
	Arch          string `json:"arch"`
	GNUBuildID    string `json:"gnu_build_id"`
	GoBuildID     string `json:"go_build_id"`
	FileHash      string `json:"file_hash"`
	Type          string `json:"type"`
	SymbolSource  string `json:"symbol_source"`
	Origin        string `json:"origin"`
	OriginVersion string `json:"origin_version"`
	FileName      string `json:"filename"`
}

func newSymbolUploadRequestMetadata(e *elfSymbols, symbolSource SymbolSource, profilerVersion string) *symbolUploadRequestMetadata {
	return &symbolUploadRequestMetadata{
		Arch:          runtime.GOARCH,
		GNUBuildID:    e.gnuBuildID,
		GoBuildID:     e.goBuildID,
		FileHash:      e.fileHash,
		Type:          "elf_symbol_file",
		Origin:        "dd-otel-host-profiler",
		OriginVersion: profilerVersion,
		SymbolSource:  symbolSource.String(),
		FileName:      filepath.Base(e.filePath),
	}
}

func (d *DatadogSymbolUploader) handleSymbols(ctx context.Context, symbols *elfSymbols, ind int) error {
	symbolFile, err := os.CreateTemp("", "objcopy-debug")
	if err != nil {
		return fmt.Errorf("failed to create temp file to extract symbols: %w", err)
	}
	defer os.Remove(symbolFile.Name())
	defer symbolFile.Close()

	ctx, cancel := context.WithTimeout(ctx, symbolCopyTimeout)
	defer cancel()

	symbolSource := d.getSymbolSource(symbols)
	var goPCLnTabInfo *pclntab.GoPCLnTabInfo
	if symbols.isGolang && d.uploadGoPCLnTab {
		goPCLnTabInfo = symbols.getGoPCLnTab()
		if goPCLnTabInfo != nil {
			symbolSource = max(symbolSource, GoPCLnTab)
		}
	}

	err = CopySymbols(ctx, symbols.getPath(), symbolFile.Name(), goPCLnTabInfo)
	if err != nil {
		return fmt.Errorf("failed to copy symbols: %w", err)
	}

	err = d.uploadSymbols(ctx, symbolFile, newSymbolUploadRequestMetadata(symbols, symbolSource, d.version), ind)
	if err != nil {
		return fmt.Errorf("failed to upload symbols: %w", err)
	}

	return nil
}

func CopySymbols(ctx context.Context, inputPath, outputPath string, goPCLnTabInfo *pclntab.GoPCLnTabInfo) error {
	args := []string{
		"--only-keep-debug",
		"--remove-section=.gdb_index",
	}

	if goPCLnTabInfo != nil {
		// Dump gopclntab data to a temporary file
		gopclntabFile, err := os.CreateTemp("", "gopclntab")
		if err != nil {
			return fmt.Errorf("failed to create temp file to extract GoPCLnTab: %w", err)
		}
		defer os.Remove(gopclntabFile.Name())
		defer gopclntabFile.Close()

		_, err = gopclntabFile.Write(goPCLnTabInfo.Data)
		if err != nil {
			return fmt.Errorf("failed to write GoPCLnTab: %w", err)
		}

		var gofuncFile *os.File
		if goPCLnTabInfo.GoFuncData != nil {
			// Dump gofunc data to a temporary file
			gofuncFile, err = os.CreateTemp("", "gofunc")
			if err != nil {
				return fmt.Errorf("failed to create temp file to extract GoFunc: %w", err)
			}
			defer os.Remove(gofuncFile.Name())
			defer gofuncFile.Close()
			_, err = gofuncFile.Write(goPCLnTabInfo.GoFuncData)
			if err != nil {
				return fmt.Errorf("failed to write GoFunc: %w", err)
			}
		}

		// objcopy does not support extracting debug information (with `--only-keep-debug`) and keeping
		// some non-debug sections (like gopclntab) at the same time.
		// `--only-keep-debug` does not really remove non-debug sections, it keeps their memory size
		// but makes their file size 0 by marking them NOBITS (effectively zeroing them).
		// That's why we extract debug information and at the same time remove `.gopclntab` section (with
		// with `--remove-section=.gopclntab`) and add it back from the temporary file.
		args = append(args,
			"--remove-section=.gopclntab",
			"--remove-section=.data.rel.ro.gopclntab",
			"--add-section", ".gopclntab="+gopclntabFile.Name(),
			"--set-section-flags", ".gopclntab=readonly",
			fmt.Sprintf("--change-section-address=.gopclntab=%d", goPCLnTabInfo.Address))

		if gofuncFile != nil {
			args = append(args, "--add-section", ".gofunc="+gofuncFile.Name(),
				"--set-section-flags", ".gofunc=readonly",
				fmt.Sprintf("--change-section-address=.gofunc=%d", goPCLnTabInfo.GoFuncAddr),
				"--strip-symbol", "go:func.*",
				"--add-symbol", "go:func.*=.gofunc:0")
		}
	}

	args = append(args, inputPath, outputPath)

	_, err := exec.CommandContext(ctx, "objcopy", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to extract debug symbols: %w", cleanCmdError(err))
	}
	return nil
}

func (d *DatadogSymbolUploader) uploadSymbols(ctx context.Context, symbolFile *os.File,
	e *symbolUploadRequestMetadata, ind int) error {
	req, err := d.buildSymbolUploadRequest(ctx, symbolFile, e, ind)
	if err != nil {
		return fmt.Errorf("failed to build symbol upload request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("error while uploading symbols to %s: %s, %s", d.intakeURLs[ind], resp.Status, string(respBody))
	}

	return nil
}

func (d *DatadogSymbolUploader) buildSymbolUploadRequest(ctx context.Context, symbolFile *os.File,
	e *symbolUploadRequestMetadata, ind int) (*http.Request, error) {
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

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, d.intakeURLs[ind], b)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	r.Header.Set("Dd-Api-Key", d.symbolEndpoints[ind].APIKey)
	r.Header.Set("Dd-Evp-Origin", profilerName)
	r.Header.Set("Dd-Evp-Origin-Version", d.version)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Content-Encoding", "zstd")
	return r, nil
}

func (d *DatadogSymbolUploader) ResetCallCountToSymbolQueryEndpoint() int {
	callCount := 0
	for _, symbolQuerier := range d.symbolQueriers {
		callCount += symbolQuerier.ResetCallCount()
	}
	return callCount
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
