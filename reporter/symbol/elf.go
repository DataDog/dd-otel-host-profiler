// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package symbol

import (
	"errors"
	"fmt"
	"os"
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
	goPCLnTabInfo    *pclntab.GoPCLnTabInfo
	goPCLnTabInfoErr error

	dynamicSymbolsDump *DynamicSymbolsDump
	elfDataDump        string
}

type DynamicSymbolsDump struct {
	DynSymPath  string
	DynStrPath  string
	DynSymAddr  uint64
	DynStrAddr  uint64
	DynSymAlign uint64
	DynStrAlign uint64
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
	if e.dynamicSymbolsDump != nil {
		e.dynamicSymbolsDump.Remove()
	}
	if e.elfDataDump != "" {
		os.Remove(e.elfDataDump)
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

func (e *Elf) GoPCLnTab() (*pclntab.GoPCLnTabInfo, error) {
	if e.goPCLnTabInfoErr == nil && e.goPCLnTabInfo == nil {
		e.goPCLnTabInfo, e.goPCLnTabInfoErr = e.goPCLnTab()
	}
	return e.goPCLnTabInfo, e.goPCLnTabInfoErr
}

func (e *Elf) goPCLnTab() (*pclntab.GoPCLnTabInfo, error) {
	if !e.isGolang {
		return nil, errors.New("not a Go executable")
	}

	goPCLnTab, err := pclntab.FindGoPCLnTab(e.wrapper.elfFile)
	if err != nil {
		return nil, err
	}

	return goPCLnTab, nil
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

func (e *Elf) DumpElfData() (string, error) {
	if e.elfDataDump != "" {
		return e.elfDataDump, nil
	}
	elfDataDump, err := e.wrapper.DumpElfData()
	if err != nil {
		return "", err
	}
	e.elfDataDump = elfDataDump
	return elfDataDump, nil
}

func (e *Elf) DumpDynamicSymbols() (*DynamicSymbolsDump, error) {
	if e.dynamicSymbolsDump != nil {
		return e.dynamicSymbolsDump, nil
	}
	dynamicSymbolsDump, err := e.wrapper.DumpDynamicSymbols()
	if err != nil {
		return nil, err
	}
	e.dynamicSymbolsDump = dynamicSymbolsDump
	return dynamicSymbolsDump, nil
}

func (d *DynamicSymbolsDump) Remove() {
	os.Remove(d.DynSymPath)
	os.Remove(d.DynStrPath)
}

func NewElfForTest(arch, gnuBuildID, goBuildID, fileHash string) *Elf {
	return &Elf{
		arch:       arch,
		gnuBuildID: gnuBuildID,
		goBuildID:  goBuildID,
		fileHash:   fileHash,
	}
}

func NewElfFromDisk(path string) (*Elf, error) {
	fileID, err := libpf.FileIDFromExecutableFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file ID: %w", err)
	}

	return NewElf(path, fileID, &DiskOpener{})
}

type DiskOpener struct{}

func (o *DiskOpener) Open(path string) (reader process.ReadAtCloser, actualPath string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	return f, fmt.Sprintf("/proc/%v/fd/%v", os.Getpid(), f.Fd()), nil
}
