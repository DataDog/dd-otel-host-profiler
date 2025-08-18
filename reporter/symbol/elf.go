// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package symbol

import (
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"

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
	fileID     libpf.FileID

	separateSymbols *elfWrapperWithSource

	// Cached value set during the first call to getGoPCLnTab
	goPCLnTabInfo    *pclntab.GoPCLnTabInfo
	goPCLnTabInfoErr error

	elfDataDump string
}

func NewElf(filePath string, opener reporter.FileOpener, gnuBuildID, goBuildID string, fileID libpf.FileID) (*Elf, error) {
	wrapper, err := newElfWrapperFromFile(filePath, opener)
	if err != nil {
		return nil, fmt.Errorf("failed to create elf wrapper from mapping: %w", err)
	}
	return newElf(wrapper, fileID, gnuBuildID, goBuildID)
}

func NewElfForTest(arch, gnuBuildID, goBuildID string, fileID libpf.FileID) *Elf {
	return &Elf{
		arch:       arch,
		gnuBuildID: gnuBuildID,
		goBuildID:  goBuildID,
		fileID:     fileID,
	}
}

func NewElfFromDisk(filePath string) (*Elf, error) {
	fileID, err := libpf.FileIDFromExecutableFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file ID: %w", err)
	}

	wrapper, err := newElfWrapperFromFile(filePath, &DiskOpener{})
	if err != nil {
		return nil, fmt.Errorf("failed to create elf wrapper for file %s from disk: %w", filePath, err)
	}

	goBuildID := ""
	gnuBuildID, err := wrapper.elfFile.GetBuildID()
	if err != nil {
		log.Debugf("failed to get GNU build ID for file %s: %s", filePath, err)
	}

	if wrapper.elfFile.IsGolang() {
		goBuildID, err = wrapper.elfFile.GetGoBuildID()
		if err != nil {
			log.Debugf("failed to get Go build ID for file %s: %s", filePath, err)
		}
	}

	return newElf(wrapper, fileID, gnuBuildID, goBuildID)
}

func (e *Elf) FileHash() string {
	return e.fileID.StringNoQuotes()
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
	return e.wrapper.filePath
}

func (e *Elf) Close() {
	e.wrapper.Close()

	if e.separateSymbols != nil {
		e.separateSymbols.wrapper.Close()
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

func (e *Elf) SymbolPathOnDisk() string {
	if e.separateSymbols != nil && e.separateSymbols.symbolSource > e.symbolSource {
		return e.separateSymbols.wrapper.GetPersistentPath()
	}

	return e.wrapper.GetPersistentPath()
}

func (e *Elf) String() string {
	hasPCLnTab := e.HasGoPCLnTabInfo()
	symbolSource := e.SymbolSource()
	if hasPCLnTab {
		symbolSource = max(symbolSource, SourceGoPCLnTab)
	}
	return fmt.Sprintf("%s, arch=%s, gnu_build_id=%s, go_build_id=%s, file_hash=%s, symbol_source=%s, has_gopclntab=%t",
		e.wrapper.filePath, e.arch, e.gnuBuildID, e.goBuildID, e.FileHash(), symbolSource, hasPCLnTab,
	)
}

func (e *Elf) DumpElfData() (string, error) {
	if e.elfDataDump != "" {
		return e.elfDataDump, nil
	}

	elfData, err := e.wrapper.ElfData()
	if err != nil {
		return "", fmt.Errorf("failed to get elf data: %w", err)
	}

	tempFile, err := os.CreateTemp("", "elf")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file to dump elf data: %w", err)
	}

	defer tempFile.Close()

	_, err = tempFile.Write(elfData)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write elf data to temp file: %w", err)
	}

	e.elfDataDump = tempFile.Name()
	return e.elfDataDump, nil
}

func (e *Elf) GetSectionsRequiredForDynamicSymbols() []SectionInfo {
	return e.wrapper.GetSectionsRequiredForDynamicSymbols()
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

func newElf(wrapper *elfWrapper, fileID libpf.FileID, gnuBuildID, goBuildID string) (*Elf, error) {
	elf := &Elf{
		elfWrapperWithSource: elfWrapperWithSource{
			wrapper:      wrapper,
			symbolSource: wrapper.symbolSource(),
		},
		arch:       runtime.GOARCH,
		isGolang:   wrapper.elfFile.IsGolang(),
		fileID:     fileID,
		gnuBuildID: gnuBuildID,
		goBuildID:  goBuildID,
	}

	buildID, err := wrapper.elfFile.GetBuildID()
	if err != nil {
		log.Debugf(
			"Unable to get GNU build ID for executable %s: %s", wrapper.filePath, err)
	} else {
		elf.gnuBuildID = buildID
	}

	if elf.isGolang {
		goBuildID, err := wrapper.elfFile.GetGoBuildID()
		if err != nil {
			log.Debugf(
				"Unable to get Go build ID for executable %s: %s", wrapper.filePath, err)
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

type diskFile struct {
	*os.File
}

func (f *diskFile) OpenablePath() string {
	return path.Join("/proc", strconv.Itoa(os.Getpid()), "fd", strconv.Itoa(int(f.Fd())))
}

func (f *diskFile) OSFile() (*os.File, error) {
	return f.File, nil
}

type DiskOpener struct{}

func (o *DiskOpener) OpenFile(filePath string) (process.ProcessFile, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	return &diskFile{f}, nil
}
