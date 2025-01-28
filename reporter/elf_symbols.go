package reporter

import (
	"fmt"
	"runtime"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
)

type elfWrapperWithSource struct {
	wrapper *elfWrapper
	source  SymbolSource
}

type elfSymbols struct {
	elfWrapperWithSource

	arch       string
	isGolang   bool
	goBuildID  string
	gnuBuildID string
	fileHash   string
	filePath   string

	separateSymbols *elfWrapperWithSource

	// Cached value set during the first call to getGoPCLnTab
	goPCLnTabInfo *pclntab.GoPCLnTabInfo
}

func newElfSymbols(filePath string, fileID libpf.FileID, opener process.FileOpener) (*elfSymbols, error) {
	wrapper, err := openELF(filePath, opener)

	// This can happen for short-lived processes that are already gone by the time
	// we try to upload symbols
	if err != nil {
		return nil, fmt.Errorf("executable not found: %s, %w", filePath, err)
	}

	symbols := &elfSymbols{
		elfWrapperWithSource: elfWrapperWithSource{
			wrapper: wrapper,
			source:  wrapper.symbolSource(),
		},
		arch:     runtime.GOARCH,
		isGolang: wrapper.elfFile.IsGolang(),
		filePath: filePath,
		fileHash: fileID.StringNoQuotes(),
	}

	buildID, err := wrapper.elfFile.GetBuildID()
	if err != nil {
		log.Debugf(
			"Unable to get GNU build ID for executable %s: %s", filePath, err)
	} else {
		symbols.gnuBuildID = buildID
	}

	if symbols.isGolang {
		goBuildID, err := wrapper.elfFile.GetGoBuildID()
		if err != nil {
			log.Debugf(
				"Unable to get Go build ID for executable %s: %s", filePath, err)
		} else {
			symbols.goBuildID = goBuildID
		}
	}

	if symbols.source < DebugInfo {
		separateSymbols := wrapper.findSeparateSymbolsWithDebugInfo()
		if separateSymbols != nil {
			symbols.separateSymbols = &elfWrapperWithSource{
				wrapper: separateSymbols,
				source:  DebugInfo,
			}
		}
	}

	return symbols, nil
}

func (e *elfSymbols) close() {
	e.wrapper.Close()

	if e.separateSymbols != nil {
		e.separateSymbols.wrapper.Close()
	}
}

func (e *elfSymbols) symbolSource() SymbolSource {
	source := e.source

	if e.separateSymbols != nil {
		source = max(source, e.separateSymbols.source)
	}

	return source
}

func (e *elfSymbols) getGoPCLnTab() *pclntab.GoPCLnTabInfo {
	if !e.isGolang {
		return nil
	}
	if e.goPCLnTabInfo != nil {
		return e.goPCLnTabInfo
	}

	goPCLnTab, err := pclntab.FindGoPCLnTab(e.wrapper.elfFile)
	if err != nil {
		log.Debugf("Failed to find GoPCLnTab for executable %s: %v", e.filePath, err)
		return nil
	}

	e.goPCLnTabInfo = goPCLnTab

	return goPCLnTab
}

func (e *elfSymbols) getPath() string {
	if e.separateSymbols != nil && e.separateSymbols.source > e.source {
		return e.separateSymbols.wrapper.actualFilePath
	}

	return e.wrapper.actualFilePath
}

func (e *elfSymbols) String() string {
	// TODO: add more information
	return fmt.Sprintf(
		"%s, arch=%s, gnu_build_id=%s, go_build_id=%s, file_hash=%s"+
			", symbol_source=%s",
		e.filePath, e.arch, e.gnuBuildID, e.goBuildID, e.fileHash,
		e.symbolSource(),
	)
}
