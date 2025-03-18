// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package symbol

import (
	"fmt"
	"runtime"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"

	"github.com/DataDog/dd-otel-host-profiler/pclntab"
)

type elfWrapperWithSource struct {
	wrapper      *elfWrapper
	symbolSource Source
}

type Elf struct {
	elfWrapperWithSource

	arch       string
	isGolang   bool
	goBuildID  string
	gnuBuildID string
	fileHash   string
	path       string
	fileID     libpf.FileID

	separateSymbols *elfWrapperWithSource

	// Cached value set during the first call to getGoPCLnTab
	goPCLnTabInfo *pclntab.GoPCLnTabInfo
}

func NewElf(path string, fileID libpf.FileID, opener process.FileOpener) (*Elf, error) {
	wrapper, err := openELF(path, opener)

	// This can happen for short-lived processes that are already gone by the time
	// we try to upload symbols
	if err != nil {
		return nil, fmt.Errorf("executable not found: %s, %w", path, err)
	}

	elf := &Elf{
		elfWrapperWithSource: elfWrapperWithSource{
			wrapper:      wrapper,
			symbolSource: wrapper.symbolSource(),
		},
		arch:     runtime.GOARCH,
		isGolang: wrapper.elfFile.IsGolang(),
		path:     path,
		fileHash: fileID.StringNoQuotes(),
		fileID:   fileID,
	}

	buildID, err := wrapper.elfFile.GetBuildID()
	if err != nil {
		log.Debugf(
			"Unable to get GNU build ID for executable %s: %s", path, err)
	} else {
		elf.gnuBuildID = buildID
	}

	if elf.isGolang {
		goBuildID, err := wrapper.elfFile.GetGoBuildID()
		if err != nil {
			log.Debugf(
				"Unable to get Go build ID for executable %s: %s", path, err)
		} else {
			elf.goBuildID = goBuildID
		}
	}

	if elf.symbolSource < SourceDebugInfo {
		separateSymbols := wrapper.findSeparateSymbolsWithDebugInfo()
		if separateSymbols != nil {
			elf.separateSymbols = &elfWrapperWithSource{
				wrapper:      separateSymbols,
				symbolSource: SourceDebugInfo,
			}
		}
	}

	return elf, nil
}

func (e *Elf) FileHash() string {
	return e.fileHash
}

func (e *Elf) FileID() libpf.FileID {
	return e.fileID
}

func (e *Elf) GnuBuildID() string {
	return e.gnuBuildID
}

func (e *Elf) GoBuildID() string {
	return e.goBuildID
}

func (e *Elf) IsGolang() bool {
	return e.isGolang
}

func (e *Elf) Arch() string {
	return e.arch
}

func (e *Elf) Path() string {
	return e.path
}

func (e *Elf) Close() {
	e.wrapper.Close()

	if e.separateSymbols != nil {
		e.separateSymbols.wrapper.Close()
	}
}

func (e *Elf) SymbolSource() Source {
	source := e.symbolSource

	if e.separateSymbols != nil {
		source = max(source, e.separateSymbols.symbolSource)
	}

	return source
}

func (e *Elf) HasGoPCLnTabInfo() bool {
	return e.goPCLnTabInfo != nil
}

func (e *Elf) GoPCLnTab() *pclntab.GoPCLnTabInfo {
	if !e.isGolang {
		return nil
	}
	if e.goPCLnTabInfo != nil {
		return e.goPCLnTabInfo
	}

	goPCLnTab, err := pclntab.FindGoPCLnTab(e.wrapper.elfFile)
	if err != nil {
		log.Debugf("Failed to find SourceGoPCLnTab for executable %s: %v", e.path, err)
		return nil
	}

	e.goPCLnTabInfo = goPCLnTab

	return goPCLnTab
}

func (e *Elf) SymbolPathOnDisk() string {
	if e.separateSymbols != nil && e.separateSymbols.symbolSource > e.symbolSource {
		return e.separateSymbols.wrapper.actualFilePath
	}

	return e.wrapper.actualFilePath
}

func (e *Elf) String() string {
	hasPCLnTab := e.HasGoPCLnTabInfo()
	symbolSource := e.SymbolSource()
	if hasPCLnTab {
		symbolSource = max(symbolSource, SourceGoPCLnTab)
	}
	return fmt.Sprintf("%s, arch=%s, gnu_build_id=%s, go_build_id=%s, file_hash=%s, symbol_source=%s, has_gopclntab=%t",
		e.path, e.arch, e.gnuBuildID, e.goBuildID, e.fileHash, symbolSource, hasPCLnTab,
	)
}

func NewElfForTest(arch, gnuBuildID, goBuildID, fileHash string) *Elf {
	return &Elf{
		arch:       arch,
		gnuBuildID: gnuBuildID,
		goBuildID:  goBuildID,
		fileHash:   fileHash,
	}
}
