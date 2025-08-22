// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package reporter

import (
	"bufio"
	"encoding/binary"
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
)

type ProcessContextData struct {
	ServiceName               string `msgpack:"service.name"`
	ServiceInstanceID         string `msgpack:"service.instance.id"`
	DeploymentEnvironmentName string `msgpack:"deployment.environment.name"`
}

const mappingParseBufferSize = 256

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, mappingParseBufferSize)
		return &buf
	},
}

func getContextMapping(mapsFile io.Reader, rm remotememory.RemoteMemory) ([]byte, error) {
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

	pageSize := uint64(os.Getpagesize())
	scanner.Buffer(*scanBuf, 8192)
	for scanner.Scan() {
		var fields [6]string
		var addrs [2]string

		line := stringutil.ByteSlice2String(scanner.Bytes())
		if stringutil.FieldsN(line, fields[:]) < 5 {
			continue
		}
		if fields[1] != "r--p" || fields[4] != "0" || fields[3] != "00:00" {
			continue
		}

		if stringutil.SplitN(fields[0], "-", addrs[:]) < 2 {
			continue
		}

		isContextMapping := false
		if fields[5] == "[anon:OTEL_CTX]" {
			isContextMapping = true
		}

		if !isContextMapping && fields[5] != "" {
			continue
		}

		vaddr, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			log.Debugf("vaddr: failed to convert %s to uint64: %v", addrs[0], err)
			continue
		}
		vend, err := strconv.ParseUint(addrs[1], 16, 64)
		if err != nil {
			log.Debugf("vend: failed to convert %s to uint64: %v", addrs[1], err)
			continue
		}
		length := vend - vaddr

		if length != pageSize {
			continue
		}
		var buf [24]byte
		err = rm.Read(libpf.Address(vaddr), buf[:])
		if err != nil {
			log.Debugf("failed to read context mapping: %v", err)
			continue
		}
		if string(buf[:8]) != "OTEL_CTX" {
			continue
		}
		payloadVersion := binary.LittleEndian.Uint32(buf[8:12])
		if payloadVersion != 1 {
			continue
		}
		payloadSize := binary.LittleEndian.Uint32(buf[12:16])
		payloadAddr := binary.LittleEndian.Uint64(buf[16:24])

		payload := make([]byte, payloadSize)
		err = rm.Read(libpf.Address(payloadAddr), payload)
		if err != nil {
			log.Debugf("failed to read payload: %v", err)
			continue
		}
		return payload, nil
	}
	return nil, errors.New("no context mapping found")
}

func ReadProcessLevelContext(pid libpf.PID) (ProcessContextData, error) {
	mapsFile, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		log.Debugf("failed to open maps file: %v", err)
		return ProcessContextData{}, err
	}
	defer mapsFile.Close()

	rm := remotememory.NewProcessVirtualMemory(pid)
	data, err := getContextMapping(mapsFile, rm)
	if err != nil {
		return ProcessContextData{}, err
	}
	var ctx ProcessContextData
	err = msgpack.Unmarshal(data, &ctx)
	if err != nil {
		log.Debugf("failed to unmarshal context mapping: %v", err)
		return ProcessContextData{}, err
	}
	return ctx, nil
}
