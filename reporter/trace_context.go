// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/stringutil"

	samples "github.com/DataDog/dd-otel-host-profiler/reporter/samples"
)

const (
	mappingParseBufferSize = 256
	otelContextMappingName = "[anon:OTEL_CTX]"
	otelContextSignature   = "OTEL_CTX"
	maxPayloadSize         = 1024
)

// expect a two-page sized mapping
var otelContextMappingSize = uint64(os.Getpagesize() * 2)

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, mappingParseBufferSize)
		return &buf
	},
}

type processContextHeader struct {
	Signature   [8]byte
	Version     uint32
	PayloadSize uint32
	PayloadAddr uintptr
}

func getContextFromMapping(fields *[6]string, rm remotememory.RemoteMemory) []byte {
	if fields[1] != "r--p" || fields[4] != "0" || fields[3] != "00:00" {
		return nil
	}

	var addrs [2]string
	if stringutil.SplitN(fields[0], "-", addrs[:]) < 2 {
		return nil
	}

	vaddr, err := strconv.ParseUint(addrs[0], 16, 64)
	if err != nil {
		log.Debugf("vaddr: failed to convert %s to uint64: %v", addrs[0], err)
		return nil
	}

	vend, err := strconv.ParseUint(addrs[1], 16, 64)
	if err != nil {
		log.Debugf("vend: failed to convert %s to uint64: %v", addrs[1], err)
		return nil
	}

	length := vend - vaddr
	if length != otelContextMappingSize {
		return nil
	}

	// Make CodeQL happy, this will never happen since we build only for 64-bit architectures
	if vaddr > uint64(^libpf.Address(0)) {
		return nil
	}

	var header processContextHeader
	err = rm.Read(libpf.Address(vaddr), libpf.SliceFrom(&header))
	if err != nil {
		log.Debugf("failed to read context mapping: %v", err)
		return nil
	}
	if stringutil.ByteSlice2String(header.Signature[:]) != otelContextSignature {
		return nil
	}
	if header.Version != 1 {
		return nil
	}
	if header.PayloadSize > maxPayloadSize {
		return nil
	}

	payload := make([]byte, header.PayloadSize)
	err = rm.Read(libpf.Address(header.PayloadAddr), payload)
	if err != nil {
		log.Debugf("failed to read context payload: %v", err)
		return nil
	}
	return payload
}

func getContextMapping(mapsFile io.Reader, rm remotememory.RemoteMemory, useMappingNames bool) ([]byte, error) {
	scanner := bufio.NewScanner(mapsFile)
	scanBuf, ok := bufPool.Get().(*[]byte)
	if !ok {
		return nil, errors.New("failed to get memory from sync pool")
	}
	defer func() {
		// Reset memory and return it for reuse.
		for j := range *scanBuf {
			(*scanBuf)[j] = 0x0
		}
		bufPool.Put(scanBuf)
	}()

	scanner.Buffer(*scanBuf, 8192)
	for scanner.Scan() {
		var fields [6]string

		line := stringutil.ByteSlice2String(scanner.Bytes())
		if stringutil.FieldsN(line, fields[:]) < 5 {
			continue
		}

		if (useMappingNames && fields[5] != otelContextMappingName) || (!useMappingNames && fields[5] != "") {
			continue
		}

		payload := getContextFromMapping(&fields, rm)
		if payload != nil {
			return payload, nil
		}

		if useMappingNames {
			// When using mapping names, we can stop after the first match.
			break
		}
	}
	return nil, errors.New("no context mapping found")
}

func readProcessContext(mapsFile io.Reader, rm remotememory.RemoteMemory, useMappingNames bool) (*samples.ProcessContext, error) {
	data, err := getContextMapping(mapsFile, rm, useMappingNames)
	if err != nil {
		return nil, err
	}
	var ctx samples.ProcessContext
	err = msgpack.Unmarshal(data, &ctx)
	if err != nil {
		log.Warnf("failed to unmarshal context mapping: %v", err)
		return nil, err
	}
	return &ctx, nil
}

func ReadProcessLevelContext(pid libpf.PID, useMappingNames bool) (*samples.ProcessContext, error) {
	mapsFile, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		log.Debugf("failed to open maps file: %v", err)
		return nil, err
	}
	defer mapsFile.Close()

	rm := remotememory.NewProcessVirtualMemory(pid)
	return readProcessContext(mapsFile, rm, useMappingNames)
}
