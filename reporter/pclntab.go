package reporter

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

type version int

const (
	verUnknown version = iota
	ver12
	ver116
	ver118
	ver120

	ptrSize           = 8
	maxBytesGoPclntab = 128 * 1024 * 1024
	// pclntabHeader magic identifying Go version
	magicGo1_2  = 0xfffffffb
	magicGo1_16 = 0xfffffffa
	magicGo1_18 = 0xfffffff0
	magicGo1_20 = 0xfffffff1
)

type GoPCLnTabInfo struct {
	Address    uint64  // goPCLnTab address
	Data       []byte  // goPCLnTab data
	Version    version // gopclntab header version
	Offsets    TableOffsets
	GoFuncAddr uint64 // goFunc address
	GoFuncData []byte // goFunc data
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

// pclntabFuncMap is the Golang function symbol table map entry
type pclntabFuncMap struct {
	pc      uint64
	funcOff uint64
}

// pclntabFunc is the Golang function definition (struct _func in the spec) as before Go 1.18.
type pclntabFunc struct {
	startPc                      uint64
	nameOff, argsSize, frameSize int32
	pcspOff, pcfileOff, pclnOff  int32
	nfuncData, npcData           int32
}

// pclntabFunc118 is the Golang function definition (struct _func in the spec)
// starting with Go 1.18.
// see: go/src/runtime/runtime2.go (struct _func)
type pclntabFunc118 struct {
	entryoff                     uint32 // start pc, as offset from pcHeader.textStart
	nameOff, argsSize, frameSize int32
	pcspOff, pcfileOff, pclnOff  int32
	nfuncData, npcData           int32
}

// getInt32 gets a 32-bit integer from the data slice at offset with bounds checking
func getInt32(data []byte, offset int) int {
	if offset < 0 || offset+4 > len(data) {
		return -1
	}
	return int(*(*int32)(unsafe.Pointer(&data[offset])))
}

// PclntabHeaderSize returns the minimal pclntab header size.
func PclntabHeaderSize() int {
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

func goFuncOffset(v version) (uint32, error) {
	if v < ver118 {
		return 0, fmt.Errorf("unsupported version: %v", v)
	}
	if v < ver120 {
		return 38 * ptrSize, nil
	}
	return 40 * ptrSize, nil
}

func FindModuleData(ef *pfelf.File, goPCLnTabInfo *GoPCLnTabInfo, symtab *libpf.SymbolMap) ([]byte, uint64, error) {
	// First try to locate module data by looking for runtime.firstmoduledata symbol.
	if symtab != nil {
		if symAddr, err := symtab.LookupSymbolAddress("runtime.firstmoduledata"); err == nil {
			addr := uint64(symAddr)
			section := sectionContaining(ef, addr)
			if section == nil {
				return nil, 0, fmt.Errorf("could not find section containing runtime.firstmoduledata")
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

	// asume here that pointer size is 8
	const ptrSize = 8
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

	return nil, 0, fmt.Errorf("could not find moduledata")
}

func FindGoFunc(ef *pfelf.File, goPCLnTabInfo *GoPCLnTabInfo, symtab *libpf.SymbolMap) ([]byte, uint64, error) {
	// First try to locate goFunc with go:func.* symbol.
	if symtab != nil {
		if goFuncAddr, err := symtab.LookupSymbolAddress("go:func.*"); err == nil {
			addr := uint64(goFuncAddr)
			sec := sectionContaining(ef, addr)
			if sec != nil {
				secData, err := sec.Data(maxBytesGoPclntab)
				if err != nil {
					return nil, 0, fmt.Errorf("could not read section containing gofunc: %w", err)
				}
				return secData[addr-sec.Addr:], addr, nil
			}
		}
	}

	moduleData, _, err := FindModuleData(ef, goPCLnTabInfo, symtab)
	if err != nil {
		return nil, 0, fmt.Errorf("could not find module data: %w", err)
	}
	goFuncOff, err := goFuncOffset(goPCLnTabInfo.Version)
	if err != nil {
		return nil, 0, fmt.Errorf("could not get go func offset: %w", err)
	}
	if goFuncOff+ptrSize >= uint32(len(moduleData)) {
		return nil, 0, fmt.Errorf("invalid go func offset: %v", goFuncOff)
	}
	goFuncVal := binary.LittleEndian.Uint64(moduleData[goFuncOff:])
	sec := sectionContaining(ef, goFuncVal)
	if sec == nil {
		return nil, 0, fmt.Errorf("could not find section containing gofunc")
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

func SearchGoPclntab(ef *pfelf.File) ([]byte, uint64, error) {
	signature := pclntabHeaderSignature(ef.Machine)

	for i := range ef.Progs {
		p := ef.Progs[i]
		// Search for the .rodata (read-only) and .data.rel.ro (read-write which gets
		// turned into read-only after relocations handling via GNU_RELRO header).
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == elf.PF_X || p.Flags&elf.PF_R != elf.PF_R {
			continue
		}

		data, err := p.Data(maxBytesGoPclntab)
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

func FindGoPCLnTab(ef *pfelf.File, useHeuristicSearchAsFallback bool) (goPCLnTabInfo *GoPCLnTabInfo, err error) {
	// gopclntab parsing code might panic if the data is corrupt.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while searching pclntab: %v", r)
		}
	}()

	var data []byte
	var goPCLnTabAddr uint64
	var symtab *libpf.SymbolMap

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
			if !useHeuristicSearchAsFallback {
				return nil, fmt.Errorf("failed to read symbols and heuristic search disabled: %w", err)
			}
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
		} else {
			start, err := symtab.LookupSymbolAddress("runtime.pclntab")
			if err != nil {
				return nil, fmt.Errorf("failed to load .gopclntab via symbols: %w", err)
			}
			end, err := symtab.LookupSymbolAddress("runtime.epclntab")
			if err != nil {
				return nil, fmt.Errorf("failed to load .gopclntab via symbols: %w", err)
			}
			if start >= end {
				return nil, fmt.Errorf("invalid .gopclntab symbols: %v-%v", start, end)
			}
			data = make([]byte, end-start)
			if _, err := ef.ReadVirtualMemory(data, int64(start)); err != nil {
				return nil, fmt.Errorf("failed to load .gopclntab via symbols: %w", err)
			}
			goPCLnTabAddr = uint64(start)
		}
	}

	if data == nil {
		return nil, nil
	}

	version := verUnknown
	var offsets TableOffsets
	hdrSize := uintptr(PclntabHeaderSize())
	mapSize := unsafe.Sizeof(pclntabFuncMap{})
	// funSize := unsafe.Sizeof(pclntabFunc{})
	dataLen := uintptr(len(data))
	if dataLen < hdrSize {
		return nil, fmt.Errorf(".gopclntab is too short (%v)", len(data))
	}
	// var textStart uintptr
	// var functab, funcdata, funcnametab, filetab, pctab, cutab []byte

	hdr := (*pclntabHeader)(unsafe.Pointer(&data[0]))
	// fieldSize := uintptr(hdr.ptrSize)
	switch hdr.magic {
	case magicGo1_2:
		version = ver12
		functabEnd := int(hdrSize + uintptr(hdr.numFuncs)*mapSize + uintptr(hdr.ptrSize))
		filetabOffset := getInt32(data, functabEnd)
		numSourceFiles := getInt32(data, filetabOffset)
		if filetabOffset == 0 || numSourceFiles == 0 {
			return nil, fmt.Errorf(".gopclntab corrupt (filetab 0x%x, nfiles %d)",
				filetabOffset, numSourceFiles)
		}
		// functab = data[hdrSize:filetabOffset]
		// cutab = data[filetabOffset:]
		// pctab = data
		// funcnametab = data
		// funcdata = data
		// filetab = data
		offsets = TableOffsets{
			FuncTabOffset: uint64(hdrSize),
			CuTabOffset:   uint64(filetabOffset),
		}
	case magicGo1_16:
		version = ver116
		hdrSize = unsafe.Sizeof(pclntabHeader116{})
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
		// funcnametab = data[hdr116.funcnameOffset:]
		// cutab = data[hdr116.cuOffset:]
		// filetab = data[hdr116.filetabOffset:]
		// pctab = data[hdr116.pctabOffset:]
		// functab = data[hdr116.pclnOffset:]
		// funcdata = functab
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
		} else {
			version = ver118
		}
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
		// funcnametab = data[hdr118.funcnameOffset:]
		// cutab = data[hdr118.cuOffset:]
		// filetab = data[hdr118.filetabOffset:]
		// pctab = data[hdr118.pctabOffset:]
		// functab = data[hdr118.pclnOffset:]
		// funcdata = functab
		// textStart = hdr118.textStart
		// funSize = unsafe.Sizeof(pclntabFunc118{})
		// With the change of the type of the first field of _func in Go 1.18, this
		// value is now hard coded.
		//
		//nolint:lll
		// See https://github.com/golang/go/blob/6df0957060b1315db4fd6a359eefc3ee92fcc198/src/debug/gosym/pclntab.go#L376-L382
		// fieldSize = uintptr(4)
		// mapSize = fieldSize * 2
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

	goPCLnTabInfo = &GoPCLnTabInfo{Address: goPCLnTabAddr, Data: data, Version: version, Offsets: offsets}

	// Only search for goFunc if the version is 1.18 or later and heuristic search is enabled.
	// Note that GoFuncData will extend to the end of the section containing goFunc (usually .rodata).
	// That's why we return it only if heuristic search is enabled.
	if version >= ver118 && useHeuristicSearchAsFallback {
		if symtab == nil {
			symtab, _ = ef.ReadSymbols()
		}
		goFuncData, goFuncAddr, err := FindGoFunc(ef, goPCLnTabInfo, symtab)
		if err == nil {
			goPCLnTabInfo.GoFuncAddr = goFuncAddr
			goPCLnTabInfo.GoFuncData = goFuncData
		}
	}
	return goPCLnTabInfo, nil
}
