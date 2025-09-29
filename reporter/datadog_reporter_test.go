// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	pprofile "github.com/google/pprof/profile"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestGetServiceName(t *testing.T) {
	tests := []struct {
		name           string
		environContent string
		expectedResult string
	}{
		{
			name:           "DD_SERVICE found",
			environContent: "PATH=/usr/bin\x00DD_SERVICE=my-service\x00HOME=/home/user\x00",
			expectedResult: "my-service",
		},
		{
			name:           "OTEL_SERVICE_NAME found",
			environContent: "PATH=/usr/bin\x00OTEL_SERVICE_NAME=otel-service\x00HOME=/home/user\x00",
			expectedResult: "otel-service",
		},
		{
			name:           "DD_SERVICE takes precedence over OTEL_SERVICE_NAME",
			environContent: "OTEL_SERVICE_NAME=otel-service\x00DD_SERVICE=dd-service\x00PATH=/usr/bin\x00",
			expectedResult: "dd-service",
		},
		{
			name:           "DD_SERVICE takes precedence over OTEL_SERVICE_NAME (reverse order)",
			environContent: "DD_SERVICE=dd-service\x00OTEL_SERVICE_NAME=otel-service\x00PATH=/usr/bin\x00",
			expectedResult: "dd-service",
		},
		{
			name:           "no service environment variables",
			environContent: "PATH=/usr/bin\x00HOME=/home/user\x00USER=testuser\x00",
			expectedResult: "",
		},
		{
			name:           "empty environment",
			environContent: "",
			expectedResult: "",
		},
		{
			name:           "DD_SERVICE with empty value",
			environContent: "PATH=/usr/bin\x00DD_SERVICE=\x00HOME=/home/user\x00",
			expectedResult: "",
		},
		{
			name:           "OTEL_SERVICE_NAME with empty value",
			environContent: "PATH=/usr/bin\x00OTEL_SERVICE_NAME=\x00HOME=/home/user\x00",
			expectedResult: "",
		},
		{
			name:           "service name with special characters",
			environContent: "DD_SERVICE=my-service_123.test-app\x00PATH=/usr/bin\x00",
			expectedResult: "my-service_123.test-app",
		},
		{
			name:           "service name with spaces",
			environContent: "DD_SERVICE=my service name\x00PATH=/usr/bin\x00",
			expectedResult: "my service name",
		},
		{
			name:           "service name with equals sign in value",
			environContent: "DD_SERVICE=service=with=equals\x00PATH=/usr/bin\x00",
			expectedResult: "service=with=equals",
		},
		{
			name:           "malformed environment variable without equals",
			environContent: "PATH=/usr/bin\x00DD_SERVICE_NO_EQUALS\x00HOME=/home/user\x00",
			expectedResult: "",
		},
		{
			name:           "partial match should not work",
			environContent: "MY_DD_SERVICE=should-not-match\x00DD_SERVICE_SUFFIX=also-not-match\x00",
			expectedResult: "",
		},
		{
			name:           "case sensitive matching",
			environContent: "dd_service=lowercase\x00DD_service=mixed\x00PATH=/usr/bin\x00",
			expectedResult: "",
		},
		{
			name:           "multiple null terminators",
			environContent: "PATH=/usr/bin\x00\x00DD_SERVICE=test-service\x00\x00HOME=/home/user\x00",
			expectedResult: "test-service",
		},
		{
			name:           "OTEL_SERVICE_NAME when DD_SERVICE has empty value",
			environContent: "DD_SERVICE=\x00OTEL_SERVICE_NAME=backup-service\x00PATH=/usr/bin\x00",
			expectedResult: "backup-service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory and file to simulate /proc/{pid}/environ
			tmpDir := t.TempDir()
			testPID := libpf.PID(12345)
			procDir := filepath.Join(tmpDir, "proc", fmt.Sprintf("%d", testPID))
			err := os.MkdirAll(procDir, 0o755)
			require.NoError(t, err)

			environFile := filepath.Join(procDir, "environ")
			err = os.WriteFile(environFile, []byte(tt.environContent), 0o600)
			require.NoError(t, err)

			// Test the environment variable parsing logic directly
			result := parseServiceNameFromEnvironData([]byte(tt.environContent))
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGetServiceName_FileNotFound(t *testing.T) {
	// Test with a PID that doesn't exist
	nonExistentPID := libpf.PID(999999)
	result := getServiceName(nonExistentPID)
	assert.Empty(t, result, "Should return empty string when /proc/{pid}/environ doesn't exist")
}

func TestGetServiceName_FileReadError(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()
	testPID := libpf.PID(12345)
	procDir := filepath.Join(tmpDir, "proc", fmt.Sprintf("%d", testPID))
	err := os.MkdirAll(procDir, 0o755)
	require.NoError(t, err)

	// Create an environ file with no read permissions
	environFile := filepath.Join(procDir, "environ")
	err = os.WriteFile(environFile, []byte("DD_SERVICE=test\x00"), 0o000) // No permissions
	require.NoError(t, err)

	result := getServiceNameFromProcPath(testPID, tmpDir)
	assert.Empty(t, result, "Should return empty string when file cannot be read")
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid characters preserved",
			input:    "my-service_v1.2",
			expected: "my-service_v1.2",
		},
		{
			name:     "invalid characters replaced",
			input:    "service:name*with?chars",
			expected: "service_name_with_chars",
		},
		{
			name:     "unicode characters removed",
			input:    "service-\u540D\u524D-\U0001F680", // Unicode: 名前🚀
			expected: "service--",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReportProfile_FilenameGeneration(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Create a minimal config for testing
	cfg := &Config{
		PprofPrefix: filepath.Join(tmpDir, "temp"),
		IntakeURL:   "http://localhost:8126",
		Version:     "test",
	}

	// Create a minimal DatadogReporter instance
	reporter := &DatadogReporter{
		config:      cfg,
		fileCounter: 0,
	}

	// Create a minimal profile
	profile := &pprofile.Profile{
		SampleType: []*pprofile.ValueType{
			{Type: "samples", Unit: "count"},
		},
		Sample: []*pprofile.Sample{
			{Value: []int64{1}},
		},
	}

	now := time.Now()

	// Test multiple profiles to ensure uniqueness
	services := []string{"service-a", "service-b"}

	for _, service := range services {
		data := &uploadProfileData{
			profile:  profile,
			start:    now.Add(-time.Minute),
			end:      now,
			entityID: "ci-abc123456789defghijklmnop",
			tags: Tags{
				MakeTag("service", service),
			},
		}

		// Report each profile (ignore upload errors)
		_ = reporter.reportProfile(t.Context(), data)
	}

	// Check that exactly two files were created
	files, err := filepath.Glob(filepath.Join(tmpDir, "*.pprof"))
	require.NoError(t, err)
	require.Len(t, files, 2, "Expected exactly two pprof files to be created")

	// Verify expected filename pattern: temp-service-entityID-timestamp-counter.pprof
	expectedPattern := `temp-service-[ab]-abc123456789-\d{8}T\d{6}Z-[12]\.pprof`
	for _, file := range files {
		filename := filepath.Base(file)
		assert.Regexp(t, expectedPattern, filename, "Filename should match expected pattern")
	}
}
