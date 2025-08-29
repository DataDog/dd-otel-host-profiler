// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package reporter

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"

	samples "github.com/DataDog/dd-otel-host-profiler/reporter/samples"
)

type mockMemory struct {
	data map[uint64][]byte
}

func newMockMemory() *mockMemory {
	return &mockMemory{
		data: make(map[uint64][]byte),
	}
}

// Implement the io.ReaderAt interface for mockMemory
func (m *mockMemory) ReadAt(p []byte, off int64) (n int, err error) {
	data, exists := m.data[uint64(off)]
	if !exists {
		return 0, errors.New("address not found")
	}

	if len(p) > len(data) {
		return 0, errors.New("buffer too small")
	}

	copy(p, data[:len(p)])
	return len(p), nil
}

func (m *mockMemory) setData(addr uint64, data []byte) {
	m.data[addr] = data
}

func newMockRemoteMemory(headerAddr uint64, header []byte, payloadAddr uint64, payload []byte) remotememory.RemoteMemory {
	mockMemory := newMockMemory()
	if header != nil {
		mockMemory.setData(headerAddr, header)
	}
	if payload != nil {
		mockMemory.setData(payloadAddr, payload)
	}
	return remotememory.RemoteMemory{
		ReaderAt: mockMemory,
	}
}

func newEmptyRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{
		ReaderAt: newMockMemory(),
	}
}

// Helper function to create a valid OTEL context header
func createOTELContextHeader(payloadSize uint32, payloadAddr uint64) []byte {
	header := processContextHeader{
		Version:     1,
		PayloadSize: payloadSize,
		PayloadAddr: uintptr(payloadAddr),
	}
	copy(header.Signature[:], otelContextSignature)
	return libpf.SliceFrom(&header)
}

// Helper function to create msgpack encoded ProcessContextData
func createProcessContextPayload() ([]byte, samples.ProcessContext) {
	ctx := samples.ProcessContext{
		ServiceName:               "test-service",
		ServiceVersion:            "v1.2.3",
		ServiceInstanceID:         "instance-123",
		DeploymentEnvironmentName: "production",
		HostName:                  "test-host",
		TelemetrySdkLanguage:      "go",
		TelemetrySdkName:          "opentelemetry",
		TelemetrySdkVersion:       "1.0.0",
	}

	payload, err := msgpack.Marshal(ctx)
	if err != nil {
		panic(err)
	}

	return payload, ctx
}

func TestReadProcessContext_Success(t *testing.T) {
	// Create test payload
	payload, expectedCtx := createProcessContextPayload()

	// Create OTEL context header
	headerAddr := uint64(0x1000)
	payloadAddr := uint64(0x20000)
	header := createOTELContextHeader(uint32(len(payload)), payloadAddr)

	// Create mock maps file content
	mapsContent := "1000-3000 r--p 00000000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	// Create mock remote memory
	rm := newMockRemoteMemory(headerAddr, header, payloadAddr, payload)

	// Test with useMappingNames = false
	ctx, err := readProcessContext(mapsReader, rm, false)

	require.NoError(t, err)
	assert.Equal(t, expectedCtx.ServiceName, ctx.ServiceName)
	assert.Equal(t, expectedCtx.ServiceVersion, ctx.ServiceVersion)
	assert.Equal(t, expectedCtx.ServiceInstanceID, ctx.ServiceInstanceID)
	assert.Equal(t, expectedCtx.DeploymentEnvironmentName, ctx.DeploymentEnvironmentName)
	assert.Equal(t, expectedCtx.HostName, ctx.HostName)
	assert.Equal(t, expectedCtx.TelemetrySdkLanguage, ctx.TelemetrySdkLanguage)
	assert.Equal(t, expectedCtx.TelemetrySdkName, ctx.TelemetrySdkName)
	assert.Equal(t, expectedCtx.TelemetrySdkVersion, ctx.TelemetrySdkVersion)
}

func TestReadProcessContext_SuccessWithMappingNames(t *testing.T) {
	// Create test payload
	payload, expectedCtx := createProcessContextPayload()

	// Create OTEL context header
	headerAddr := uint64(0x2000)
	payloadAddr := uint64(0x30000)
	header := createOTELContextHeader(uint32(len(payload)), payloadAddr)

	// Create mock remote memory
	rm := newMockRemoteMemory(headerAddr, header, payloadAddr, payload)

	// Create mock maps file content with mapping name
	mapsContent := "2000-4000 r--p 00000000 00:00 0 " + otelContextMappingName + "\n"
	mapsReader := strings.NewReader(mapsContent)

	// Test with useMappingNames = true
	ctx, err := readProcessContext(mapsReader, rm, true)

	require.NoError(t, err)
	assert.Equal(t, expectedCtx.ServiceName, ctx.ServiceName)
	assert.Equal(t, expectedCtx.ServiceVersion, ctx.ServiceVersion)
	assert.Equal(t, expectedCtx.ServiceInstanceID, ctx.ServiceInstanceID)
	assert.Equal(t, expectedCtx.DeploymentEnvironmentName, ctx.DeploymentEnvironmentName)
	assert.Equal(t, expectedCtx.HostName, ctx.HostName)
	assert.Equal(t, expectedCtx.TelemetrySdkLanguage, ctx.TelemetrySdkLanguage)
	assert.Equal(t, expectedCtx.TelemetrySdkName, ctx.TelemetrySdkName)
	assert.Equal(t, expectedCtx.TelemetrySdkVersion, ctx.TelemetrySdkVersion)
}

func TestReadProcessContext_NoContextMappingFound(t *testing.T) {
	rm := newEmptyRemoteMemory()

	// Create mock maps file without valid context mapping
	mapsContent := "7fff12345000-7fff12346000 rw-p 00000000 00:00 0 [stack]\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_InvalidMappingSize(t *testing.T) {
	rm := newEmptyRemoteMemory()

	// Create mock maps file with wrong size mapping (not two pages)
	mapsContent := "1000-1800 r--p 00000000 00:00 0\n" // 0x800 bytes instead of two pages
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_InvalidSignature(t *testing.T) {
	// Create invalid header with wrong signature
	headerAddr := uint64(0x1000)
	invalidHeader := processContextHeader{
		Version:     1,
		PayloadSize: 100,
		PayloadAddr: uintptr(0x2000),
	}
	copy(invalidHeader.Signature[:], "INVALID_") // Wrong signature

	rm := newMockRemoteMemory(headerAddr, libpf.SliceFrom(&invalidHeader), 0, nil)

	mapsContent := "1000-3000 r--p 00000000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_InvalidVersion(t *testing.T) {
	// Create header with invalid version
	headerAddr := uint64(0x1000)
	invalidHeader := processContextHeader{
		Version:     2, // Wrong version
		PayloadSize: 100,
		PayloadAddr: uintptr(0x2000),
	}
	copy(invalidHeader.Signature[:], otelContextSignature)

	rm := newMockRemoteMemory(headerAddr, libpf.SliceFrom(&invalidHeader), 0, nil)

	mapsContent := "1000-3000 r--p 00000000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_PayloadReadError(t *testing.T) {
	// Create valid header but fail on payload read
	headerAddr := uint64(0x1000)
	payloadAddr := uint64(0x3000)
	header := createOTELContextHeader(100, payloadAddr)

	rm := newMockRemoteMemory(headerAddr, header, payloadAddr, nil)
	// Don't set payload data, causing read error

	mapsContent := "1000-3000 r--p 00000000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_MsgpackUnmarshalError(t *testing.T) {
	// Create valid header but invalid msgpack payload
	headerAddr := uint64(0x1000)
	payloadAddr := uint64(0x4000)
	invalidPayload := []byte("invalid msgpack data")
	header := createOTELContextHeader(uint32(len(invalidPayload)), payloadAddr)

	rm := newMockRemoteMemory(headerAddr, header, payloadAddr, invalidPayload)

	mapsContent := "1000-3000 r--p 00000000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Nil(t, ctx)
}

func TestReadProcessContext_WrongPermissions(t *testing.T) {
	rm := newEmptyRemoteMemory()

	// Create mock maps file with wrong permissions (not r--p)
	mapsContent := "1000-3000 rw-p 00000000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_NonZeroOffset(t *testing.T) {
	rm := newEmptyRemoteMemory()

	// Create mock maps file with non-zero offset (should be rejected)
	mapsContent := "1000-3000 r--p 00001000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_EmptyMapsFile(t *testing.T) {
	rm := newEmptyRemoteMemory()

	// Empty maps file
	mapsReader := strings.NewReader("")

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_MalformedMapsLine(t *testing.T) {
	rm := newEmptyRemoteMemory()

	// Malformed maps line (insufficient fields)
	mapsContent := "1000-2000 r--p\n"
	mapsReader := strings.NewReader(mapsContent)

	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}

func TestReadProcessContext_TooLargePayload(t *testing.T) {
	// Test with payload size significantly exceeding maxPayloadSize

	// Create a very large payload (10KB)
	hugePayload := make([]byte, 10240)
	for i := range hugePayload {
		hugePayload[i] = byte(i % 256)
	}

	headerAddr := uint64(0x1000)
	payloadAddr := uint64(0x2000)
	header := createOTELContextHeader(uint32(len(hugePayload)), payloadAddr)

	rm := newMockRemoteMemory(headerAddr, header, payloadAddr, hugePayload)

	mapsContent := "1000-3000 r--p 00000000 00:00 0\n"
	mapsReader := strings.NewReader(mapsContent)

	// This should fail due to payload size significantly exceeding the limit
	ctx, err := readProcessContext(mapsReader, rm, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no context mapping found")
	assert.Nil(t, ctx)
}
