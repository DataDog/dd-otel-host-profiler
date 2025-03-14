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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/zstd"
	lru "github.com/elastic/go-freelru"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
	"github.com/DataDog/dd-otel-host-profiler/reporter/symbol"
)

const (
	uploadCacheSize = 16384

	defaultRetrievalWorkerCount = 10
	defaultRetrievalQueueSize   = 1000

	defaultBatcherQueueSize        = 1000
	defaultSymbolQueryMaxBatchSize = 100

	defaultQueryQueueSize = 1000

	defaultUploadWorkerCount = 10
	defaultUploadQueueSize   = 1000

	sourceMapEndpoint = "/api/v2/srcmap"

	symbolCopyTimeout = 10 * time.Second
	uploadTimeout     = 15 * time.Second
)

type fileData struct {
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

	uploadCache    *lru.SyncedLRU[libpf.FileID, struct{}]
	client         *http.Client
	symbolQueriers []SymbolQuerier

	retrievalWorkerCount int
	retrievalQueue       chan fileData
	retrievalWg          sync.WaitGroup

	clock            clockwork.Clock
	batchingQueue    chan *symbol.Elf
	batchingInterval time.Duration
	batchingMaxSize  int
	batchingWg       sync.WaitGroup

	queryQueue chan []*symbol.Elf
	queryWg    sync.WaitGroup

	uploadWorkerCount int
	uploadQueue       chan *ElfWithBackendSources
	uploadWg          sync.WaitGroup
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
	var symbolQueriers = make([]SymbolQuerier, len(cfg.SymbolEndpoints))

	for i, endpoints := range cfg.SymbolEndpoints {
		var symbolQuerier SymbolQuerier
		intakeURLs[i] = buildSourcemapIntakeURL(endpoints.Site)

		if symbolQuerier, err = NewDatadogSymbolQuerier(endpoints.Site, endpoints.APIKey, endpoints.AppKey); err != nil {
			return nil, fmt.Errorf("failed to create Datadog symbol querier: %w", err)
		}
		symbolQueriers[i] = symbolQuerier
	}

	uploadCache, err := lru.NewSynced[libpf.FileID, struct{}](uploadCacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	symbolQueryMaxBatchSize := defaultSymbolQueryMaxBatchSize
	if cfg.SymbolQueryInterval <= 0 {
		symbolQueryMaxBatchSize = 1
	}

	return &DatadogSymbolUploader{
		symbolEndpoints:      cfg.SymbolEndpoints,
		intakeURLs:           intakeURLs,
		version:              cfg.Version,
		dryRun:               cfg.DryRun,
		uploadDynamicSymbols: cfg.UploadDynamicSymbols,
		uploadGoPCLnTab:      cfg.UploadGoPCLnTab,
		client:               &http.Client{Timeout: uploadTimeout},
		uploadCache:          uploadCache,
		symbolQueriers:       symbolQueriers,

		retrievalWorkerCount: defaultRetrievalWorkerCount,
		retrievalQueue:       make(chan fileData, defaultRetrievalQueueSize),

		clock:            clockwork.NewRealClock(),
		batchingQueue:    make(chan *symbol.Elf, defaultBatcherQueueSize),
		batchingInterval: cfg.SymbolQueryInterval,
		batchingMaxSize:  symbolQueryMaxBatchSize,

		queryQueue: make(chan []*symbol.Elf, defaultQueryQueueSize),

		uploadWorkerCount: defaultUploadWorkerCount,
		uploadQueue:       make(chan *ElfWithBackendSources, defaultUploadQueueSize),
	}, nil
}

func buildSourcemapIntakeURL(site string) string {
	return fmt.Sprintf("https://sourcemap-intake.%s%s", site, sourceMapEndpoint)
}

func (d *DatadogSymbolUploader) overrideClock(clock clockwork.Clock) {
	d.clock = clock
}

func (d *DatadogSymbolUploader) retrievalWorker(ctx context.Context) {
	for {
		select {
		case file, ok := <-d.retrievalQueue:
			if !ok {
				d.retrievalWg.Done()
				return
			}
			// Record immediately to avoid duplicate uploads
			d.uploadCache.Add(file.fileID, struct{}{})
			elf := d.getSymbolsFromDisk(file)
			if elf == nil {
				// Remove from cache because we might have symbols for this exe in another context
				d.uploadCache.Remove(file.fileID)
				continue
			}

			d.batchingQueue <- elf
		case <-ctx.Done():
			d.retrievalWg.Done()
			return
		}
	}
}

func (d *DatadogSymbolUploader) batchingWorker(ctx context.Context) {
	var batch []*symbol.Elf
	var ticker <-chan time.Time
	if d.batchingInterval > 0 {
		ticker = d.clock.NewTicker(d.batchingInterval).Chan()
	}

	flush := func() {
		if len(batch) > 0 {
			d.queryQueue <- batch
			batch = nil
		}
	}

	flushThenStop := func() {
		flush()
		d.batchingWg.Done()
	}

	for {
		select {
		case <-ctx.Done():
			flushThenStop()
			return
		case in, ok := <-d.batchingQueue:
			if !ok {
				flushThenStop()
				return
			}
			batch = append(batch, in)
			if d.batchingMaxSize > 0 && len(batch) >= d.batchingMaxSize {
				flush()
			}
		case <-ticker:
			flush()
		}
	}
}

func (d *DatadogSymbolUploader) queryWorker(ctx context.Context) {
	for {
		select {
		case batch, ok := <-d.queryQueue:
			if !ok {
				d.queryWg.Done()
				return
			}
			batchRes := ExecuteSymbolQueryBatch(ctx, batch, d.symbolQueriers)
			for _, res := range batchRes {
				d.uploadQueue <- res
			}
		case <-ctx.Done():
			d.queryWg.Done()
			return
		}
	}
}

func (d *DatadogSymbolUploader) uploadWorker(ctx context.Context) {
	for {
		select {
		case elf, ok := <-d.uploadQueue:
			if !ok {
				d.uploadWg.Done()
				return
			}
			// TODO: upload symbols to endpoints concurrently (beware of gopclntab extraction that is not thread-safe)
			removeFromCache := false
			for i, backendSymbolSource := range elf.BackendSymbolSources {
				if backendSymbolSource.Err != nil {
					log.Warnf("Failed to query symbols for executable %s: %v", elf, backendSymbolSource.Err)
					removeFromCache = true
					continue
				}

				log.Debugf("Existing symbols for executable %s: %v", elf, backendSymbolSource)

				if !d.upload(ctx, elf.Elf, backendSymbolSource.SymbolSource, i) {
					// Remove from cache to retry later
					removeFromCache = true
				}
			}

			if removeFromCache {
				d.uploadCache.Remove(elf.FileID())
			}
			elf.Close()

		case <-ctx.Done():
			d.uploadWg.Done()
			return
		}
	}
}

func (d *DatadogSymbolUploader) Start(ctx context.Context) {
	for range d.retrievalWorkerCount {
		d.retrievalWg.Add(1)
		go d.retrievalWorker(ctx)
	}

	d.batchingWg.Add(1)
	go d.batchingWorker(ctx)

	d.queryWg.Add(1)
	go d.queryWorker(ctx)

	for range d.uploadWorkerCount {
		d.uploadWg.Add(1)
		go d.uploadWorker(ctx)
	}
}

func (d *DatadogSymbolUploader) Stop() {
	close(d.retrievalQueue)
	d.retrievalWg.Wait()

	close(d.batchingQueue)
	d.batchingWg.Wait()

	close(d.queryQueue)
	d.queryWg.Wait()

	close(d.uploadQueue)
	d.uploadWg.Wait()
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
	case d.retrievalQueue <- fileData{filePath, fileID, buildID, opener}:
	default:
		log.Warnf("Symbol upload queue is full, skipping symbol upload for file %q with file ID %q and build ID %q",
			filePath, fileID.StringNoQuotes(), buildID)
	}
}

func (d *DatadogSymbolUploader) getSymbolSource(e *symbol.Elf) symbol.Source {
	source := e.SymbolSource()

	if source == symbol.SourceDynamicSymbolTable && !d.uploadDynamicSymbols {
		source = symbol.SourceNone
	}

	return source
}

func (d *DatadogSymbolUploader) getSymbolSourceIfGoPCLnTab(e *symbol.Elf) symbol.Source {
	symbolSource := d.getSymbolSource(e)
	if !e.IsGolang() || !d.uploadGoPCLnTab {
		return symbolSource
	}
	return max(symbolSource, symbol.SourceGoPCLnTab)
}

func (d *DatadogSymbolUploader) getSymbolSourceWithGoPCLnTab(e *symbol.Elf) (symbol.Source, *pclntab.GoPCLnTabInfo) {
	symbolSource := d.getSymbolSource(e)
	if !e.IsGolang() || !d.uploadGoPCLnTab {
		return symbolSource, nil
	}
	goPCLnTabInfo := e.GoPCLnTab()
	if goPCLnTabInfo == nil {
		return symbolSource, nil
	}
	return max(symbolSource, symbol.SourceGoPCLnTab), goPCLnTabInfo
}

func (d *DatadogSymbolUploader) getSymbolsFromDisk(data fileData) *symbol.Elf {
	filePath := data.filePath
	fileID := data.fileID

	elf, err := symbol.NewElf(filePath, fileID, data.opener)
	if err != nil {
		log.Debugf("Skipping symbol upload for executable %s: %v",
			data.filePath, err)
		return nil
	}

	symbolSource := d.getSymbolSourceIfGoPCLnTab(elf)
	if symbolSource == symbol.SourceNone {
		log.Debugf("Skipping symbol upload for executable %s: no debug symbols found", elf.Path())
		elf.Close()
		return nil
	}

	return elf
}

// Returns true if the upload was successful, false otherwise
func (d *DatadogSymbolUploader) upload(ctx context.Context, e *symbol.Elf, existingSymbolSource symbol.Source, ind int) bool {
	symbolSource := d.getSymbolSourceIfGoPCLnTab(e)
	if existingSymbolSource >= symbolSource {
		log.Infof("Skipping symbol upload for executable %s: existing symbols with source %v", e.Path(),
			existingSymbolSource.String())
		return true
	}

	if d.uploadGoPCLnTab {
		symbolSource, goPCLnTabInfo := d.getSymbolSourceWithGoPCLnTab(e)
		if goPCLnTabInfo == nil {
			// Fail to extract gopclntab, recheck the symbol source
			if symbolSource == symbol.SourceNone {
				log.Debugf("Skipping symbol upload for Go executable %s: no debug symbols found", e.Path())
				return false
			}
			if existingSymbolSource >= symbolSource {
				log.Infof("Skipping symbol upload for Go executable %s: existing symbols with source %v", e.Path(),
					existingSymbolSource.String())
				return true
			}
		}
	}

	if d.dryRun {
		log.Infof("Dry run: would upload symbols for executable: %s", e)
		return true
	}

	err := d.handleSymbols(ctx, e, ind)
	if err != nil {
		log.Errorf("Failed to handle symbols: %v for executable: %s", err, e)
		return false
	}

	log.Infof("Symbols uploaded successfully for executable: %s", e)
	return true
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

func newSymbolUploadRequestMetadata(e *symbol.Elf, symbolSource symbol.Source, profilerVersion string) *symbolUploadRequestMetadata {
	return &symbolUploadRequestMetadata{
		Arch:          runtime.GOARCH,
		GNUBuildID:    e.GnuBuildID(),
		GoBuildID:     e.GoBuildID(),
		FileHash:      e.FileHash(),
		Type:          "elf_symbol_file",
		Origin:        "dd-otel-host-profiler",
		OriginVersion: profilerVersion,
		SymbolSource:  symbolSource.String(),
		FileName:      filepath.Base(e.Path()),
	}
}

func (d *DatadogSymbolUploader) handleSymbols(ctx context.Context, e *symbol.Elf, ind int) error {
	symbolFile, err := os.CreateTemp("", "objcopy-debug")
	if err != nil {
		return fmt.Errorf("failed to create temp file to extract symbols: %w", err)
	}
	defer os.Remove(symbolFile.Name())
	defer symbolFile.Close()

	ctx, cancel := context.WithTimeout(ctx, symbolCopyTimeout)
	defer cancel()

	symbolSource, goPCLnTabInfo := d.getSymbolSourceWithGoPCLnTab(e)

	err = CopySymbols(ctx, e.SymbolPathOnDisk(), symbolFile.Name(), goPCLnTabInfo)
	if err != nil {
		return fmt.Errorf("failed to copy symbols: %w", err)
	}

	err = d.uploadSymbols(ctx, symbolFile, newSymbolUploadRequestMetadata(e, symbolSource, d.version), ind)
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
