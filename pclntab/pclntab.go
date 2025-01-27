// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package pclntab

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

type HeaderVersion int

const (
	verUnknown HeaderVersion = iota
	ver12
	ver116
	ver118
	ver120

	ptrSize           = 8
	maxBytesGoPclntab = 128 * 1024 * 1024
	maxGoFuncID       = 22

	funcdataInlTree = 3

	// pclntabHeader magic identifying Go version
	magicGo1_2  = 0xfffffffb
	magicGo1_16 = 0xfffffffa
	magicGo1_18 = 0xfffffff0
	magicGo1_20 = 0xfffffff1
)

var (
	disableRecover = false
)

type GoPCLnTabInfo struct {
	Address    uint64        // goPCLnTab address
	Data       []byte        // goPCLnTab data
	Version    HeaderVersion // gopclntab header version
	Offsets    TableOffsets
	GoFuncAddr uint64 // goFunc address
	GoFuncData []byte // goFunc data

	numFuncs            int
	funcSize            int
	fieldSize           int
	funcNpcdataOffset   int
	funcNfuncdataOffset int
	functab             []byte
	funcdata            []byte
}

type TableOffsets struct {
	FuncNameTabOffset uint64
	CuTabOffset       uint64
	FileTabOffset     uint64
	PcTabOffset       uint64
	FuncTabOffset     uint64
}

type pclntabHeader struct {
	// magic is one of the magicGo1_xx constants identifying the version
	magic uint32
	// pad is unused and is needed for alignment
	pad uint16
	// quantum is the CPU instruction size alignment (e.g. 1 for x86, 4 for arm)
	quantum uint8
	// ptrSize is the CPU pointer size in bytes
	ptrSize uint8
	// numFuncs is the number of function definitions to follow
	numFuncs uint64
}

type pclntabHeader116 struct {
	pclntabHeader
	nfiles         uint
	funcnameOffset uintptr
	cuOffset       uintptr
	filetabOffset  uintptr
	pctabOffset    uintptr
	pclnOffset     uintptr
}

// pclntabHeader118 is the Golang pclntab header structure starting Go 1.18
// structural definition of this is found in go/src/runtime/symtab.go as pcHeader
type pclntabHeader118 struct {
	pclntabHeader
	nfiles         uint
	textStart      uintptr
	funcnameOffset uintptr
	cuOffset       uintptr
	filetabOffset  uintptr
	pctabOffset    uintptr
	pclnOffset     uintptr
}

type rawInlinedCall112 struct {
	Parent   int16 // index of parent in the inltree, or < 0
	FuncID   uint8 // type of the called function
	padding  byte
	File     int32 // perCU file index for inlined call. See cmd/link:pcln.go
	Line     int32 // line number of the call site
	Func     int32 // offset into pclntab for name of called function
	ParentPC int32 // position of an instruction whose source position is the call site (offset from entry)
}

// rawInlinedCall120 is the encoding of entries in the FUNCDATA_InlTree table
// from Go 1.20. It is equivalent to runtime.inlinedCall.
type rawInlinedCall120 struct {
	FuncID    uint8 // type of the called function
	padding   [3]byte
	NameOff   int32 // offset into pclntab for name of called function
	ParentPC  int32 // position of an instruction whose source position is the call site (offset from entry)
	StartLine int32 // line number of start of function (func keyword/TEXT directive)
}

func (h HeaderVersion) String() string {
	switch h {
	case ver12:
		return "1.2"
	case ver116:
		return "1.16"
	case ver118:
		return "1.18"
	case ver120:
		return "1.20"
	default:
		return "unknown"
	}
}

// getInt32 gets a 32-bit integer from the data slice at offset with bounds checking
func getInt32(data []byte, offset int) int {
	if offset < 0 || offset+4 > len(data) {
		return -1
	}
	return int(*(*int32)(unsafe.Pointer(&data[offset])))
}

func getUInt32(data []byte, offset int) int {
	if offset < 0 || offset+4 > len(data) {
		return -1
	}
	return int(*(*uint32)(unsafe.Pointer(&data[offset])))
}

func getUint8(data []byte, offset int) int {
	if offset < 0 || offset+1 > len(data) {
		return -1
	}
	return int(*(*uint8)(unsafe.Pointer(&data[offset])))
}

// HeaderSize returns the minimal pclntab header size.
func HeaderSize() int {
	return int(unsafe.Sizeof(pclntabHeader{}))
}

func sectionContaining(elfFile *pfelf.File, addr uint64) *pfelf.Section {
	for _, s := range elfFile.Sections {
		if s.Type != elf.SHT_NOBITS && addr >= s.Addr && addr < s.Addr+s.Size {
			return &s
		}
	}
	return nil
}

func goFuncOffset(v HeaderVersion) (uint32, error) {
	if v < ver118 {
		return 0, fmt.Errorf("unsupported pclntab version: %v", v.String())
	}
	if v < ver120 {
		return 38 * ptrSize, nil
	}
	return 40 * ptrSize, nil
}

func FindModuleData(ef *pfelf.File, goPCLnTabInfo *GoPCLnTabInfo, symtab *libpf.SymbolMap) (data []byte, address uint64, returnedErr error) {
	// First try to locate module data by looking for runtime.firstmoduledata symbol.
	if symtab != nil {
		if symAddr, err := symtab.LookupSymbolAddress("runtime.firstmoduledata"); err == nil {
			addr := uint64(symAddr)
			section := sectionContaining(ef, addr)
			if section == nil {
				return nil, 0, errors.New("could not find section containing runtime.firstmoduledata")
			}
			data, err := section.Data(maxBytesGoPclntab)
			if err != nil {
				return nil, 0, fmt.Errorf("could not read section containing runtime.firstmoduledata: %w", err)
			}
			return data[addr-section.Addr:], addr, nil
		}
	}

	// If runtime.firstmoduledata is missing, heuristically search for gopclntab address in .noptrdata section.
	// https://www.mandiant.com/resources/blog/golang-internals-symbol-recovery
	noPtrSection := ef.Section(".noptrdata")
	noPtrSectionData, err := noPtrSection.Data(maxBytesGoPclntab)
	if err != nil {
		return nil, 0, fmt.Errorf("could not read .noptrdata section: %w", err)
	}

	var buf [2 * ptrSize]byte
	binary.NativeEndian.PutUint64(buf[:], goPCLnTabInfo.Address)
	binary.NativeEndian.PutUint64(buf[ptrSize:], goPCLnTabInfo.Address+goPCLnTabInfo.Offsets.FuncNameTabOffset)
	for i := 0; i < len(noPtrSectionData)-19*ptrSize; i += ptrSize {
		n := bytes.Index(noPtrSectionData[i:], buf[:])
		if n < 0 {
			break
		}
		i += n

		off := i + 4*ptrSize
		cuTabAddr := binary.NativeEndian.Uint64(noPtrSectionData[off:])
		off += 3 * ptrSize
		fileTabAddr := binary.NativeEndian.Uint64(noPtrSectionData[off:])
		off += 3 * ptrSize
		pcTabAddr := binary.NativeEndian.Uint64(noPtrSectionData[off:])
		off += 6 * ptrSize
		funcTabAddr := binary.NativeEndian.Uint64(noPtrSectionData[off:])

		// Check if the offsets are valid.
		if cuTabAddr != goPCLnTabInfo.Address+goPCLnTabInfo.Offsets.CuTabOffset ||
			fileTabAddr != goPCLnTabInfo.Address+goPCLnTabInfo.Offsets.FileTabOffset ||
			pcTabAddr != goPCLnTabInfo.Address+goPCLnTabInfo.Offsets.PcTabOffset ||
			funcTabAddr != goPCLnTabInfo.Address+goPCLnTabInfo.Offsets.FuncTabOffset {
			continue
		}
		return noPtrSectionData[n:], noPtrSection.Addr + uint64(n), nil
	}

	return nil, 0, errors.New("could not find moduledata")
}

func findGoFuncEnd112(data []byte) int {
	elemSize := int(unsafe.Sizeof(rawInlinedCall112{}))
	nbElem := len(data) / elemSize
	inlineCalls := unsafe.Slice((*rawInlinedCall112)(unsafe.Pointer(&data[0])), nbElem)
	for i, ic := range inlineCalls {
		if ic.padding != 0 || ic.FuncID > maxGoFuncID || ic.Line < 0 || ic.ParentPC < 0 || ic.Func < 0 {
			return i * elemSize
		}
	}
	return nbElem * elemSize
}

func findGoFuncEnd120(data []byte) int {
	elemSize := int(unsafe.Sizeof(rawInlinedCall120{}))
	nbElem := len(data) / elemSize
	inlineCalls := unsafe.Slice((*rawInlinedCall120)(unsafe.Pointer(&data[0])), nbElem)
	for i, ic := range inlineCalls {
		if ic.padding[0] != 0 || ic.padding[1] != 0 || ic.padding[2] != 0 || ic.FuncID > maxGoFuncID || ic.StartLine < 0 || ic.ParentPC < 0 || ic.NameOff < 0 {
			return i * elemSize
		}
	}
	return nbElem * elemSize
}

// Determine heuristically the end of go func data.
func findGoFuncEnd(data []byte, version HeaderVersion) int {
	if version < ver120 {
		return findGoFuncEnd112(data)
	}
	return findGoFuncEnd120(data)
}

func findGoFuncVal(ef *pfelf.File, goPCLnTabInfo *GoPCLnTabInfo, symtab *libpf.SymbolMap) (uint64, error) {
	// First try to locate goFunc with go:func.* symbol.
	if symtab != nil {
		if goFuncSym, err := symtab.LookupSymbol("go:func.*"); err == nil {
			return uint64(goFuncSym.Address), nil
		}
		if goFuncSym, err := symtab.LookupSymbol("go.func.*"); err == nil {
			return uint64(goFuncSym.Address), nil
		}
	}

	moduleData, _, err := FindModuleData(ef, goPCLnTabInfo, symtab)
	if err != nil {
		return 0, fmt.Errorf("could not find module data: %w", err)
	}
	goFuncOff, err := goFuncOffset(goPCLnTabInfo.Version)
	if err != nil {
		return 0, fmt.Errorf("could not get go func offset: %w", err)
	}
	if goFuncOff+ptrSize >= uint32(len(moduleData)) {
		return 0, fmt.Errorf("invalid go func offset: %v", goFuncOff)
	}
	goFuncVal := binary.LittleEndian.Uint64(moduleData[goFuncOff:])

	return goFuncVal, nil
}

func FindGoFunc(ef *pfelf.File, goPCLnTabInfo *GoPCLnTabInfo, symtab *libpf.SymbolMap) (data []byte, goFuncVal uint64, err error) {
	goFuncVal, err = findGoFuncVal(ef, goPCLnTabInfo, symtab)
	if err != nil {
		return nil, 0, fmt.Errorf("could not find go func: %w", err)
	}
	sec := sectionContaining(ef, goFuncVal)
	if sec == nil {
		return nil, 0, errors.New("could not find section containing gofunc")
	}
	secData, err := sec.Data(maxBytesGoPclntab)
	if err != nil {
		return nil, 0, fmt.Errorf("could not read section containing gofunc: %w", err)
	}
	return secData[goFuncVal-sec.Addr:], goFuncVal, nil
}

func pclntabHeaderSignature(arch elf.Machine) []byte {
	var quantum byte

	switch arch {
	case elf.EM_X86_64:
		quantum = 0x1
	case elf.EM_AARCH64:
		quantum = 0x4
	}

	//  - the first byte is ignored and not included in this signature
	//    as it is different per Go version (see magicGo1_XX)
	//  - next three bytes are 0xff (shared on magicGo1_XX)
	//  - pad is zero (two bytes)
	//  - quantum depends on the architecture
	//  - ptrSize is 8 for 64 bit systems (arm64 and amd64)

	return []byte{0xff, 0xff, 0xff, 0x00, 0x00, quantum, 0x08}
}

func SearchGoPclntab(ef *pfelf.File) (data []byte, address uint64, err error) {
	signature := pclntabHeaderSignature(ef.Machine)

	for i := range ef.Progs {
		p := ef.Progs[i]
		// Search for the .rodata (read-only) and .data.rel.ro (read-write which gets
		// turned into read-only after relocations handling via GNU_RELRO header).
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == elf.PF_X || p.Flags&elf.PF_R != elf.PF_R {
			continue
		}

		data, err = p.Data(maxBytesGoPclntab)
		if err != nil {
			return nil, 0, err
		}

		for i := 1; i < len(data)-16; i += 8 {
			// Search for something looking like a valid pclntabHeader header
			// Ignore the first byte on bytes.Index (differs on magicGo1_XXX)
			n := bytes.Index(data[i:], signature)
			if n < 0 {
				break
			}
			i += n - 1

			// Check the 'magic' against supported list, and if valid, use this
			// location as the .gopclntab base. Otherwise, continue just search
			// for next candidate location.
			magic := binary.LittleEndian.Uint32(data[i:])
			switch magic {
			case magicGo1_2, magicGo1_16, magicGo1_18, magicGo1_20:
				return data[i:], uint64(i) + p.Vaddr, nil
			}
		}
	}

	return nil, 0, nil
}

func (g *GoPCLnTabInfo) findMaxInlineTreeOffset() int {
	maxInlineTreeOffset := -1
	for i := range g.numFuncs {
		funcIdx := (2*i + 1) * g.fieldSize
		funcOff := getUInt32(g.functab, funcIdx)
		if funcOff == -1 {
			continue
		}
		nfuncdata := getUint8(g.funcdata, funcOff+g.funcNfuncdataOffset)
		npcdata := getUInt32(g.funcdata, funcOff+g.funcNpcdataOffset)
		if nfuncdata != -1 && npcdata != -1 && nfuncdata > funcdataInlTree {
			off := funcOff + g.funcSize + (npcdata+funcdataInlTree)*4
			inlineTreeOffset := getUInt32(g.funcdata, off)
			if inlineTreeOffset != int(^uint32(0)) && inlineTreeOffset > maxInlineTreeOffset {
				maxInlineTreeOffset = inlineTreeOffset
			}
		}
	}

	return maxInlineTreeOffset
}

func (g *GoPCLnTabInfo) findFuncDataSize() int {
	maxFuncOffset := -1
	maxFuncOffsetIdx := -1
	for i := range g.numFuncs {
		funcIdx := (2*i + 1) * g.fieldSize
		funcOff := getUInt32(g.functab, funcIdx)
		if funcOff > maxFuncOffset {
			maxFuncOffset = funcOff
			maxFuncOffsetIdx = i
		}
	}

	if maxFuncOffsetIdx == -1 {
		return -1
	}

	nfuncdata := getUint8(g.funcdata, maxFuncOffset+g.funcNfuncdataOffset)
	npcdata := getUInt32(g.funcdata, maxFuncOffset+g.funcNpcdataOffset)
	return maxFuncOffset + g.funcSize + (npcdata+nfuncdata)*4
}

func parseGoPCLnTab(data []byte) (*GoPCLnTabInfo, error) {
	var version HeaderVersion
	var offsets TableOffsets
	var funcSize, funcNpcdataOffset int
	hdrSize := uintptr(HeaderSize())

	dataLen := uintptr(len(data))
	if dataLen < hdrSize {
		return nil, fmt.Errorf(".gopclntab is too short (%v)", len(data))
	}
	var functab, funcdata []byte

	hdr := (*pclntabHeader)(unsafe.Pointer(&data[0]))
	fieldSize := int(hdr.ptrSize)
	switch hdr.magic {
	case magicGo1_2:
		version = ver12
		funcSize = ptrSize + 8*4
		funcNpcdataOffset = ptrSize + 6*4
		mapSize := uintptr(2 * ptrSize)
		functabEnd := int(hdrSize + uintptr(hdr.numFuncs)*mapSize + uintptr(hdr.ptrSize))
		filetabOffset := getInt32(data, functabEnd)
		numSourceFiles := getInt32(data, filetabOffset)
		if filetabOffset == 0 || numSourceFiles == 0 {
			return nil, fmt.Errorf(".gopclntab corrupt (filetab 0x%x, nfiles %d)",
				filetabOffset, numSourceFiles)
		}
		functab = data[hdrSize:filetabOffset]
		funcdata = data
		offsets = TableOffsets{
			FuncTabOffset: uint64(hdrSize),
			CuTabOffset:   uint64(filetabOffset),
		}
	case magicGo1_16:
		version = ver116
		hdrSize = unsafe.Sizeof(pclntabHeader116{})
		funcSize = ptrSize + 9*4
		funcNpcdataOffset = ptrSize + 6*4
		if dataLen < hdrSize {
			return nil, fmt.Errorf(".gopclntab is too short (%v)", len(data))
		}
		hdr116 := (*pclntabHeader116)(unsafe.Pointer(&data[0]))
		if dataLen < hdr116.funcnameOffset || dataLen < hdr116.cuOffset ||
			dataLen < hdr116.filetabOffset || dataLen < hdr116.pctabOffset ||
			dataLen < hdr116.pclnOffset {
			return nil, fmt.Errorf(".gopclntab is corrupt (%x, %x, %x, %x, %x)",
				hdr116.funcnameOffset, hdr116.cuOffset,
				hdr116.filetabOffset, hdr116.pctabOffset,
				hdr116.pclnOffset)
		}
		functab = data[hdr116.pclnOffset:]
		funcdata = functab
		offsets = TableOffsets{
			FuncNameTabOffset: uint64(hdr116.funcnameOffset),
			CuTabOffset:       uint64(hdr116.cuOffset),
			FileTabOffset:     uint64(hdr116.filetabOffset),
			PcTabOffset:       uint64(hdr116.pctabOffset),
			FuncTabOffset:     uint64(hdr116.pclnOffset),
		}
	case magicGo1_18, magicGo1_20:
		if hdr.magic == magicGo1_20 {
			version = ver120
			funcSize = 11 * 4
		} else {
			version = ver118
			funcSize = 10 * 4
		}
		funcNpcdataOffset = 7 * 4
		hdrSize = unsafe.Sizeof(pclntabHeader118{})
		if dataLen < hdrSize {
			return nil, fmt.Errorf(".gopclntab is too short (%v)", dataLen)
		}
		hdr118 := (*pclntabHeader118)(unsafe.Pointer(&data[0]))
		if dataLen < hdr118.funcnameOffset || dataLen < hdr118.cuOffset ||
			dataLen < hdr118.filetabOffset || dataLen < hdr118.pctabOffset ||
			dataLen < hdr118.pclnOffset {
			return nil, fmt.Errorf(".gopclntab is corrupt (%x, %x, %x, %x, %x)",
				hdr118.funcnameOffset, hdr118.cuOffset,
				hdr118.filetabOffset, hdr118.pctabOffset,
				hdr118.pclnOffset)
		}
		functab = data[hdr118.pclnOffset:]
		funcdata = functab
		fieldSize = 4
		offsets = TableOffsets{
			FuncNameTabOffset: uint64(hdr118.funcnameOffset),
			CuTabOffset:       uint64(hdr118.cuOffset),
			FileTabOffset:     uint64(hdr118.filetabOffset),
			PcTabOffset:       uint64(hdr118.pctabOffset),
			FuncTabOffset:     uint64(hdr118.pclnOffset),
		}
	default:
		return nil, fmt.Errorf(".gopclntab format (0x%x) not supported", hdr.magic)
	}
	if hdr.pad != 0 || hdr.ptrSize != 8 {
		return nil, fmt.Errorf(".gopclntab header: %x, %x", hdr.pad, hdr.ptrSize)
	}

	// nfuncdata is the last field in _func struct
	funcNfuncdataOffset := funcSize - 1

	return &GoPCLnTabInfo{
		Data:                data,
		Version:             version,
		Offsets:             offsets,
		numFuncs:            int(hdr.numFuncs),
		funcSize:            funcSize,
		fieldSize:           fieldSize,
		funcNpcdataOffset:   funcNpcdataOffset,
		funcNfuncdataOffset: funcNfuncdataOffset,
		functab:             functab,
		funcdata:            funcdata,
	}, nil
}

func FindGoPCLnTab(ef *pfelf.File) (goPCLnTabInfo *GoPCLnTabInfo, err error) {
	if !disableRecover {
		// gopclntab parsing code might panic if the data is corrupt.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic while searching pclntab: %v", r)
			}
		}()
	}

	var data []byte
	var goPCLnTabAddr uint64
	var symtab *libpf.SymbolMap

	goPCLnTabEndKnown := true
	if s := ef.Section(".gopclntab"); s != nil {
		if data, err = s.Data(maxBytesGoPclntab); err != nil {
			return nil, fmt.Errorf("failed to load .gopclntab: %w", err)
		}
		goPCLnTabAddr = s.Addr
	} else if s := ef.Section(".data.rel.ro.gopclntab"); s != nil {
		if data, err = s.Data(maxBytesGoPclntab); err != nil {
			return nil, fmt.Errorf("failed to load .data.rel.ro.gopclntab: %w", err)
		}
		goPCLnTabAddr = s.Addr
	} else if s := ef.Section(".go.buildinfo"); s != nil {
		symtab, err = ef.ReadSymbols()
		if err != nil {
			// It seems the Go binary was stripped, use the heuristic approach to get find gopclntab.
			// Note that `SearchGoPclntab` returns a slice starting from gopcltab header to the end of segment
			// containing gopclntab. Therefore this slice might contain additional data after gopclntab.
			// There does not seem to be an easy way to get the end of gopclntab segment without parsing the
			// gopclntab itself.
			if data, goPCLnTabAddr, err = SearchGoPclntab(ef); err != nil {
				return nil, fmt.Errorf("failed to search .gopclntab: %w", err)
			}
			// Truncate the data to the end of the section containing gopclntab.
			if sec := sectionContaining(ef, goPCLnTabAddr); sec != nil {
				data = data[:sec.Addr+sec.Size-goPCLnTabAddr]
			}
			goPCLnTabEndKnown = false
		} else {
			var start, end libpf.SymbolValue
			start, err = symtab.LookupSymbolAddress("runtime.pclntab")
			if err != nil {
				return nil, fmt.Errorf("failed to load .gopclntab via symbols: %w", err)
			}
			end, err = symtab.LookupSymbolAddress("runtime.epclntab")
			if err != nil {
				return nil, fmt.Errorf("failed to load .gopclntab via symbols: %w", err)
			}
			if start >= end {
				return nil, fmt.Errorf("invalid .gopclntab symbols: %v-%v", start, end)
			}
			data = make([]byte, end-start)
			if _, err = ef.ReadVirtualMemory(data, int64(start)); err != nil {
				return nil, fmt.Errorf("failed to load .gopclntab via symbols: %w", err)
			}
			goPCLnTabAddr = uint64(start)
		}
	}

	if data == nil {
		return nil, nil
	}

	goPCLnTabInfo, err = parseGoPCLnTab(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse .gopclntab: %w", err)
	}

	goPCLnTabInfo.Address = goPCLnTabAddr

	if !goPCLnTabEndKnown && goPCLnTabInfo.Version >= ver116 {
		funcDataSize := goPCLnTabInfo.findFuncDataSize()
		if funcDataSize != -1 {
			goPCLnTabSize := int(goPCLnTabInfo.Offsets.FuncTabOffset) + funcDataSize
			if goPCLnTabSize < len(goPCLnTabInfo.Data) {
				goPCLnTabInfo.Data = goPCLnTabInfo.Data[:goPCLnTabSize]
			}
		}
	}

	// Only search for goFunc if the version is 1.18 or later and heuristic search is enabled.
	if goPCLnTabInfo.Version >= ver118 {
		if symtab == nil {
			symtab, _ = ef.ReadSymbols()
		}

		goFuncData, goFuncAddr, err := FindGoFunc(ef, goPCLnTabInfo, symtab)
		if err == nil {
			goFuncEndFound := false
			if symtab != nil {
				// symbol runtime.gcbits.* follows goFunc, try to use it to determine the end of goFunc.
				nextSymAddr, err := symtab.LookupSymbolAddress("runtime.gcbits.*")
				if err == nil && uint64(nextSymAddr) > goFuncAddr {
					dist := uint64(nextSymAddr) - goFuncAddr
					if dist < uint64(len(goFuncData)) {
						goFuncData = goFuncData[:dist]
						goFuncEndFound = true
					}
				}
			}

			if !goFuncEndFound {
				// Iterate over the functions to find the maximum offset of the inline tree.
				maxInlineTreeOffset := goPCLnTabInfo.findMaxInlineTreeOffset()
				// If the inline tree offset is found, truncate the goFunc data.
				if maxInlineTreeOffset != -1 && maxInlineTreeOffset < len(goFuncData) {
					goFuncEnd := maxInlineTreeOffset + findGoFuncEnd(goFuncData[maxInlineTreeOffset:], goPCLnTabInfo.Version)
					goFuncData = goFuncData[:goFuncEnd]
				}
			}

			goPCLnTabInfo.GoFuncAddr = goFuncAddr
			goPCLnTabInfo.GoFuncData = goFuncData
		}
	}
	return goPCLnTabInfo, nil
}
