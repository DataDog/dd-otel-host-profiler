// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package symbol

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/readatbuf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

const buildIDSectionName = ".note.gnu.build-id"

var debugStrSectionNames = []string{".debug_str", ".zdebug_str", ".debug_str.dwo"}
var debugInfoSectionNames = []string{".debug_info", ".zdebug_info"}
var globalDebugDirectories = []string{"/usr/lib/debug"}

var sectionTypesToKeepForDynamicSymbols = []elf.SectionType{
	elf.SHT_GNU_HASH,
	elf.SHT_HASH,
	elf.SHT_REL,
	elf.SHT_RELA,
	elf.SHT_DYNSYM,
	elf.SHT_DYNAMIC,
	elf.SHT_GNU_VERDEF,
	elf.SHT_GNU_VERNEED,
	elf.SHT_GNU_VERSYM,
}

type elfWrapper struct {
	reader         process.ReadAtCloser
	elfFile        *pfelf.File
	filePath       string
	actualFilePath string
	opener         process.FileOpener
}

type SectionInfo struct {
	Name  string
	Flags elf.SectionFlag
}

func (e *elfWrapper) Close() {
	_ = e.reader.Close()
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
		_ = r.Close()
		return nil, err
	}
	err = ef.LoadSections()
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	return &elfWrapper{reader: r, elfFile: ef, filePath: filePath, actualFilePath: actualFilePath, opener: opener}, nil
}

func (e *elfWrapper) DumpElfData() (string, error) {
	tempElfFile, err := os.CreateTemp("", "elf")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file to dump elf data: %w", err)
	}

	defer func() {
		tempElfFile.Close()
		if err != nil {
			os.Remove(tempElfFile.Name())
		}
	}()

	_, err = io.Copy(tempElfFile, io.NewSectionReader(e.reader, 0, 1<<63-1))
	if err != nil {
		return "", fmt.Errorf("failed to dump elf data: %w", err)
	}
	return tempElfFile.Name(), nil
}

func (e *elfWrapper) GetSectionsRequiredForDynamicSymbols() []SectionInfo {
	var sections []SectionInfo
	for _, section := range e.elfFile.Sections {
		if slices.Contains(sectionTypesToKeepForDynamicSymbols, section.Type) {
			sections = append(sections, SectionInfo{Name: section.Name, Flags: section.Flags})
		}
		if section.Type == elf.SHT_DYNSYM {
			// Add STRTAB (usually .dynstr) section linked to the DYNSYM (usually .dynsym) section if it exists
			if section.Link != 0 {
				linkSection := e.elfFile.Sections[section.Link]
				sections = append(sections, SectionInfo{Name: linkSection.Name, Flags: linkSection.Flags})
			}
		}
	}

	return sections
}

func (e *elfWrapper) openELF(filePath string) (*elfWrapper, error) {
	return openELF(filePath, e.opener)
}

func (e *elfWrapper) symbolSource() Source {
	if HasDWARFData(e.elfFile) {
		return SourceDebugInfo
	}

	if e.elfFile.Section(".symtab") != nil {
		return SourceSymbolTable
	}

	if e.elfFile.Section(".dynsym") != nil {
		return SourceDynamicSymbolTable
	}

	return SourceNone
}

// findSeparateSymbolsWithDebugInfo attempts to find a separate symbol source for the elf file,
// following the same order as GDB
// https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html
func (e *elfWrapper) findSeparateSymbolsWithDebugInfo() *elfWrapper {
	log.Debugf("No debug symbols found in %s", e.filePath)

	// First, check based on the GNU build ID
	debugElf := e.findDebugSymbolsWithBuildID()
	if debugElf != nil {
		if HasDWARFData(debugElf.elfFile) {
			return debugElf
		}
		debugElf.Close()
		log.Debugf("No debug symbols found in buildID link file %s", debugElf.filePath)
	}

	// Then, check based on the debug link
	debugElf = e.findDebugSymbolsWithDebugLink()
	if debugElf != nil {
		if HasDWARFData(debugElf.elfFile) {
			return debugElf
		}
		log.Debugf("No debug symbols found in debug link file %s", debugElf.filePath)
		debugElf.Close()
	}

	return nil
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
