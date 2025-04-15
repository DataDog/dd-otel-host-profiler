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
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"golang.org/x/sync/errgroup"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
	"github.com/DataDog/dd-otel-host-profiler/reporter/pipeline"
	"github.com/DataDog/dd-otel-host-profiler/reporter/symbol"
)

const (
	uploadCacheSize = 16384

	defaultSymbolRetrievalQueueSize = 1000
	defaultRetrievalWorkerCount     = 10

	defaultSymbolBatcherQueueSize  = 1000
	defaultSymbolQueryMaxBatchSize = 100

	defaultSymbolQueryQueueSize = 1000
	defaultQueryWorkerCount     = 10

	defaultUploadQueueSize   = 1000
	defaultUploadWorkerCount = 10

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
	symbolEndpoints       []SymbolEndpoint
	intakeURLs            []string
	version               string
	dryRun                bool
	uploadDynamicSymbols  bool
	uploadGoPCLnTab       bool
	compressDebugSections bool

	uploadCache         *lru.SyncedLRU[libpf.FileID, struct{}]
	client              *http.Client
	symbolQueriers      []SymbolQuerier
	symbolQueryInterval time.Duration
	retrievalQueue      chan fileData
	pipeline            pipeline.Pipeline[fileData]
	mut                 sync.Mutex
}

type goPCLnTabDump struct {
	goPCLnTabPath string
	goFuncPath    string
}

type requestData struct {
	body            *bytes.Buffer
	contentType     string
	contentEncoding string
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

	compressDebugSections := !cfg.DisableDebugSectionCompression && CheckObjcopyZstdSupport()

	return &DatadogSymbolUploader{
		symbolEndpoints:       cfg.SymbolEndpoints,
		intakeURLs:            intakeURLs,
		version:               cfg.Version,
		dryRun:                cfg.DryRun,
		uploadDynamicSymbols:  cfg.UploadDynamicSymbols,
		uploadGoPCLnTab:       cfg.UploadGoPCLnTab,
		client:                &http.Client{Timeout: uploadTimeout},
		uploadCache:           uploadCache,
		symbolQueriers:        symbolQueriers,
		symbolQueryInterval:   cfg.SymbolQueryInterval,
		compressDebugSections: compressDebugSections,
	}, nil
}

func CheckObjcopyZstdSupport() bool {
	return exec.Command("objcopy", "--compress-debug-sections=zstd", "--version").Run() == nil
}

func buildSourcemapIntakeURL(site string) string {
	return fmt.Sprintf("https://sourcemap-intake.%s%s", site, sourceMapEndpoint)
}

func (d *DatadogSymbolUploader) symbolRetrievalWorker(_ context.Context, file fileData, outputChan chan<- *symbol.Elf) {
	// Record immediately to avoid duplicate uploads
	d.uploadCache.Add(file.fileID, struct{}{})
	elf := d.getSymbolsFromDisk(file)
	if elf == nil {
		// Remove from cache because we might have symbols for this exe in another context
		d.uploadCache.Remove(file.fileID)
		return
	}
	outputChan <- elf
}

func (d *DatadogSymbolUploader) queryWorker(ctx context.Context, batch []*symbol.Elf, outputChan chan<- ElfWithBackendSources) {
	for _, e := range ExecuteSymbolQueryBatch(ctx, batch, d.symbolQueriers) {
		outputChan <- e
	}
}

func (d *DatadogSymbolUploader) uploadWorker(ctx context.Context, elf ElfWithBackendSources) {
	var endpointIndices []int
	removeFromCache := false
	defer func() {
		if removeFromCache {
			d.uploadCache.Remove(elf.FileID())
		}
		elf.Close()
	}()

	for i, backendSymbolSource := range elf.BackendSymbolSources {
		if backendSymbolSource.Err != nil {
			log.Warnf("Failed to query symbols for executable %s: %v", elf, backendSymbolSource.Err)
			removeFromCache = true
			continue
		}

		if backendSymbolSource.SymbolSource != symbol.SourceNone {
			log.Debugf("Existing symbols for executable %s on endpoint#%d: %v", elf, i, backendSymbolSource.SymbolSource)
		}

		upload, symbolSource := d.shouldUpload(elf.Elf, backendSymbolSource.SymbolSource, i)

		if upload {
			endpointIndices = append(endpointIndices, i)
		}
		if symbolSource == symbol.SourceNone {
			// Remove from cache because we might have symbols for this exe in another context
			removeFromCache = true
		}
	}

	if len(endpointIndices) == 0 {
		return
	}

	if !d.upload(ctx, elf.Elf, endpointIndices) {
		// Remove from cache to retry later
		removeFromCache = true
	}
}

func (d *DatadogSymbolUploader) Start(ctx context.Context) {
	symbolRetrievalQueue := make(chan fileData, defaultSymbolRetrievalQueueSize)

	queryWorkerCount := defaultQueryWorkerCount
	symbolQueryMaxBatchSize := defaultSymbolQueryMaxBatchSize
	if d.symbolQueryInterval > 0 {
		queryWorkerCount = 1
	} else {
		symbolQueryMaxBatchSize = 1
	}

	symbolRetrievalStage := pipeline.NewStage(symbolRetrievalQueue,
		d.symbolRetrievalWorker,
		pipeline.WithConcurrency(defaultRetrievalWorkerCount),
		pipeline.WithOutputChanSize(defaultSymbolBatcherQueueSize))
	batchingStage := pipeline.NewBatchingStage(symbolRetrievalStage.GetOutputChannel(),
		d.symbolQueryInterval, symbolQueryMaxBatchSize,
		pipeline.WithOutputChanSize(defaultSymbolQueryQueueSize))
	queryStage := pipeline.NewStage(batchingStage.GetOutputChannel(),
		d.queryWorker,
		pipeline.WithConcurrency(queryWorkerCount),
		pipeline.WithOutputChanSize(defaultUploadQueueSize))
	uploadStage := pipeline.NewSinkStage(queryStage.GetOutputChannel(),
		d.uploadWorker,
		pipeline.WithConcurrency(defaultUploadWorkerCount))

	d.pipeline = pipeline.NewPipeline(symbolRetrievalQueue,
		symbolRetrievalStage, batchingStage, queryStage, uploadStage)
	d.pipeline.Start(ctx)

	d.mut.Lock()
	d.retrievalQueue = symbolRetrievalQueue
	d.mut.Unlock()
}

func (d *DatadogSymbolUploader) Stop() {
	d.mut.Lock()
	d.retrievalQueue = nil
	d.mut.Unlock()

	d.pipeline.Stop()
}

func (d *DatadogSymbolUploader) UploadSymbols(fileID libpf.FileID, filePath, buildID string,
	opener process.FileOpener) {
	_, ok := d.uploadCache.Get(fileID)
	if ok {
		log.Debugf("Skipping symbol upload for executable %s: already uploaded",
			filePath)
		return
	}

	d.mut.Lock()
	defer d.mut.Unlock()

	// if pipeline is not started, we can't upload symbols
	if d.retrievalQueue == nil {
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
	goPCLnTabInfo, err := e.GoPCLnTab()
	if err != nil {
		log.Infof("Failed to extract GoPCLnTab for executable %s: %v", e, err)
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

func (d *DatadogSymbolUploader) shouldUpload(e *symbol.Elf, existingSymbolSource symbol.Source, ind int) (bool, symbol.Source) {
	symbolSource := d.getSymbolSourceIfGoPCLnTab(e)
	if existingSymbolSource >= symbolSource {
		log.Infof("Skipping symbol upload for executable %s on endpoint#%d: existing symbols with source %v", e.Path(),
			ind, existingSymbolSource.String())
		return false, symbolSource
	}

	symbolSource, _ = d.getSymbolSourceWithGoPCLnTab(e)
	// Recheck symbol source after GoPCLnTab extraction
	if symbolSource == symbol.SourceNone {
		log.Debugf("Skipping symbol upload for Go executable %s on endpoint#%d: no debug symbols found", e.Path(), ind)
		return false, symbolSource
	}
	if existingSymbolSource >= symbolSource {
		log.Infof("Skipping symbol upload for Go executable %s on endpoint#%d: existing symbols with source %v", e.Path(),
			ind, existingSymbolSource.String())
		return false, symbolSource
	}

	return true, symbolSource
}

// Returns true if the upload was successful, false otherwise
func (d *DatadogSymbolUploader) upload(ctx context.Context, e *symbol.Elf, endpointIndices []int) bool {
	reqData, err := d.buildRequestData(ctx, e)
	if err != nil {
		log.Errorf("Failed to build request data for executable %s: %v", e, err)
		return false
	}

	if d.dryRun {
		log.Infof("Dry run: would upload symbols for executable: %s", e)
		return true
	}

	var g errgroup.Group
	for _, ind := range endpointIndices {
		g.Go(func() error {
			return d.uploadSymbols(ctx, reqData, ind)
		})
	}

	err = g.Wait()
	if err != nil {
		log.Errorf("Failed to upload symbols: %v for executable: %s", err, e)
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

func (d *DatadogSymbolUploader) createSymbolFile(ctx context.Context, e *symbol.Elf) (*os.File, error) {
	symbolFile, err := os.CreateTemp("", "objcopy-debug")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file to extract symbols: %w", err)
	}
	defer func() {
		if err != nil {
			symbolFile.Close()
			os.Remove(symbolFile.Name())
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, symbolCopyTimeout)
	defer cancel()

	symbolSource, goPCLnTabInfo := d.getSymbolSourceWithGoPCLnTab(e)

	elfPath := e.SymbolPathOnDisk()
	if elfPath == "" {
		// No associated file -> probably vdso, dump the ELF data to a file
		elfPath, err = e.DumpElfData()
		if err != nil {
			return nil, fmt.Errorf("failed to dump ELF data: %w", err)
		}
		// Temporary file will be cleaned by the symbol.Elf.Close()
	}

	var dynamicSymbols *symbol.DynamicSymbolsDump
	if symbolSource == symbol.SourceDynamicSymbolTable {
		// `objcopy --only-keep-debug` does not keep dynamic symbols, so we need to dump them separately and add them back
		dynamicSymbols, err = e.DumpDynamicSymbols()
		if err != nil {
			return nil, fmt.Errorf("failed to dump dynamic symbols: %w", err)
		}
		// Temporary file will be cleaned by the symbol.Elf.Close()
	}

	err = CopySymbols(ctx, elfPath, symbolFile.Name(), goPCLnTabInfo, dynamicSymbols, d.compressDebugSections)
	if err != nil {
		return nil, fmt.Errorf("failed to copy symbols: %w", err)
	}

	return symbolFile, nil
}

func dumpGoPCLnTabData(goPCLnTabInfo *pclntab.GoPCLnTabInfo) (goPCLnTabDump, error) {
	// Dump gopclntab data to a temporary file
	gopclntabFile, err := os.CreateTemp("", "gopclntab")
	if err != nil {
		return goPCLnTabDump{}, fmt.Errorf("failed to create temp file to extract GoPCLnTab: %w", err)
	}
	defer func() {
		gopclntabFile.Close()
		if err != nil {
			os.Remove(gopclntabFile.Name())
		}
	}()

	_, err = gopclntabFile.Write(goPCLnTabInfo.Data)
	if err != nil {
		return goPCLnTabDump{}, fmt.Errorf("failed to write GoPCLnTab: %w", err)
	}

	if goPCLnTabInfo.GoFuncData == nil {
		return goPCLnTabDump{goPCLnTabPath: gopclntabFile.Name()}, nil
	}

	// Dump gofunc data to a temporary file
	gofuncFile, err := os.CreateTemp("", "gofunc")
	if err != nil {
		return goPCLnTabDump{}, fmt.Errorf("failed to create temp file to extract GoFunc: %w", err)
	}
	defer func() {
		gofuncFile.Close()
		if err != nil {
			os.Remove(gofuncFile.Name())
		}
	}()

	_, err = gofuncFile.Write(goPCLnTabInfo.GoFuncData)
	if err != nil {
		return goPCLnTabDump{}, fmt.Errorf("failed to write GoFunc: %w", err)
	}

	return goPCLnTabDump{goPCLnTabPath: gopclntabFile.Name(), goFuncPath: gofuncFile.Name()}, nil
}

func CopySymbols(ctx context.Context, inputPath, outputPath string, goPCLnTabInfo *pclntab.GoPCLnTabInfo,
	dynamicSymbols *symbol.DynamicSymbolsDump, compressDebugSections bool) error {
	args := []string{
		"--only-keep-debug",
		"--remove-section=.gdb_index",
	}

	if goPCLnTabInfo != nil {
		// objcopy does not support extracting debug information (with `--only-keep-debug`) and keeping
		// some non-debug sections (like gopclntab) at the same time.
		// `--only-keep-debug` does not really remove non-debug sections, it keeps their memory size
		// but makes their file size 0 by marking them NOBITS (effectively zeroing them).
		// That's why we extract debug information and at the same time remove `.gopclntab` section (with
		// with `--remove-section=.gopclntab`) and add it back from the temporary file.
		gopclntabDump, err := dumpGoPCLnTabData(goPCLnTabInfo)
		if err != nil {
			return fmt.Errorf("failed to dump GoPCLnTab data: %w", err)
		}
		defer gopclntabDump.Remove()

		args = append(args,
			"--remove-section=.gopclntab",
			"--remove-section=.data.rel.ro.gopclntab",
			"--add-section", ".gopclntab="+gopclntabDump.goPCLnTabPath,
			"--set-section-flags", ".gopclntab=readonly",
			fmt.Sprintf("--change-section-address=.gopclntab=%d", goPCLnTabInfo.Address))

		if gopclntabDump.goFuncPath != "" {
			args = append(args, "--add-section", ".gofunc="+gopclntabDump.goFuncPath,
				"--set-section-flags", ".gofunc=readonly",
				fmt.Sprintf("--change-section-address=.gofunc=%d", goPCLnTabInfo.GoFuncAddr),
				"--strip-symbol", "go:func.*",
				"--add-symbol", "go:func.*=.gofunc:0")
		}
	}

	if dynamicSymbols != nil {
		args = append(args,
			"--remove-section=.dynsym",
			"--remove-section=.dynstr",
			"--add-section", ".dynsym="+dynamicSymbols.DynSymPath,
			"--add-section", ".dynstr="+dynamicSymbols.DynStrPath,
			fmt.Sprintf("--change-section-address=.dynsym=%d", dynamicSymbols.DynSymAddr),
			fmt.Sprintf("--change-section-address=.dynstr=%d", dynamicSymbols.DynStrAddr),
			fmt.Sprintf("--set-section-alignment=.dynsym=%d", dynamicSymbols.DynSymAlign),
			fmt.Sprintf("--set-section-alignment=.dynstr=%d", dynamicSymbols.DynStrAlign))
	}

	if compressDebugSections {
		args = append(args, "--compress-debug-sections=zstd")
	}

	args = append(args, inputPath, outputPath)

	_, err := exec.CommandContext(ctx, "objcopy", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to extract debug symbols: %w", cleanCmdError(err))
	}
	return nil
}

func (d *DatadogSymbolUploader) uploadSymbols(ctx context.Context, reqData *requestData, endpointIdx int) error {
	req, err := d.buildSymbolUploadRequest(ctx, reqData, endpointIdx)
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

		return fmt.Errorf("error while uploading symbols to %s: %s, %s", d.intakeURLs[endpointIdx], resp.Status, string(respBody))
	}

	return nil
}

func (d *DatadogSymbolUploader) buildRequestData(ctx context.Context, e *symbol.Elf) (*requestData, error) {
	symbolFile, err := d.createSymbolFile(ctx, e)
	if err != nil {
		return nil, fmt.Errorf("failed to create symbol file: %w", err)
	}
	defer os.Remove(symbolFile.Name())
	defer symbolFile.Close()

	symbolSource, _ := d.getSymbolSourceWithGoPCLnTab(e)
	return buildRequestBody(symbolFile, newSymbolUploadRequestMetadata(e, symbolSource, d.version), !d.compressDebugSections)
}

func buildRequestBody(symbolFile *os.File, e *symbolUploadRequestMetadata, compress bool) (*requestData, error) {
	b := new(bytes.Buffer)

	var compressed *zstd.Writer
	var mw *multipart.Writer
	if compress {
		compressed = zstd.NewWriter(b)
		mw = multipart.NewWriter(compressed)
	} else {
		mw = multipart.NewWriter(b)
	}

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

	encoding := ""
	if compress {
		err = compressed.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to close zstd writer: %w", err)
		}
		encoding = "zstd"
	}

	r := &requestData{body: b, contentType: mw.FormDataContentType(), contentEncoding: encoding}
	return r, nil
}

func (d *DatadogSymbolUploader) buildSymbolUploadRequest(ctx context.Context, reqData *requestData, ind int) (*http.Request, error) {
	// Do not pass directly the request body to the upload function because it might be consumed by multiple requests
	b := bytes.NewReader(reqData.body.Bytes())
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, d.intakeURLs[ind], b)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	r.Header.Set("Dd-Api-Key", d.symbolEndpoints[ind].APIKey)
	r.Header.Set("Dd-Evp-Origin", profilerName)
	r.Header.Set("Dd-Evp-Origin-Version", d.version)
	r.Header.Set("Content-Type", reqData.contentType)
	if reqData.contentEncoding != "" {
		r.Header.Set("Content-Encoding", reqData.contentEncoding)
	}
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

func (g *goPCLnTabDump) Remove() {
	os.Remove(g.goPCLnTabPath)
	if g.goFuncPath != "" {
		os.Remove(g.goFuncPath)
	}
}
