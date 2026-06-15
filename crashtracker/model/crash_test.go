package model_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DataDog/dd-otel-host-profiler/crashtracker/model"
)

func TestCrashInfoMarshalRoundTrip(t *testing.T) {
	crash := model.CrashInfo{
		DataSchemaVersion: model.SchemaVersion,
		Error: model.ErrorData{
			IsCrash:    true,
			Kind:       model.ErrorKindUnixSignal,
			Message:    "Process terminated with SEGV_MAPERR (SIGSEGV)",
			SourceType: "Crashtracking",
			ThreadName: "main",
			Stack: &model.StackTrace{
				Format: model.StackTraceFormat,
				Frames: []model.StackFrame{
					{
						IP:              "0x00007f7e11d3a2b0",
						RelativeAddress: "0x3a2b0",
						Path:            "/usr/lib/x86_64-linux-gnu/libc.so.6",
						BuildID:         "69389d485a9793dbe873f0ea2c93e02efaa9aa3d",
						BuildIDType:     model.BuildIDGNU,
						FileType:        model.FileTypeELF,
						Function:        "strlen",
					},
				},
				Incomplete: false,
			},
		},
		Incomplete: false,
		Metadata: model.Metadata{
			LibraryName:    "dd-ebpf-crashtracker",
			LibraryVersion: "0.1.0",
			Family:         "native",
			Tags:           []string{"service:nginx", "env:production"},
		},
		OsInfo: model.OsInfo{
			Architecture: "x86_64",
			Bitness:      "64-bit",
			OsType:       "Linux",
			Version:      "6.8.0-45-generic",
		},
		ProcInfo: &model.ProcInfo{
			PID: 12345,
			TID: 12347,
		},
		SigInfo: &model.SigInfo{
			SiSigno:              11,
			SiSignoHumanReadable: model.SignalSIGSEGV,
			SiCode:               1,
			SiCodeHumanReadable:  model.CodeSEGV_MAPERR,
			SiAddr:               "0x0000000000001234",
		},
		Ucontext: &model.Ucontext{
			Arch: "x86_64",
			Registers: map[string]string{
				"rip": "0x00007f7e11d3a2b0",
				"rsp": "0x00007ffee3b4c8a0",
				"rbp": "0x00007ffee3b4c910",
			},
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		UUID:      "f7e2a1b3-4c5d-6e7f-8a9b-0c1d2e3f4a5b",
	}

	data, err := json.MarshalIndent(crash, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify round-trip
	var decoded model.CrashInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.DataSchemaVersion != model.SchemaVersion {
		t.Errorf("schema version: got %q, want %q", decoded.DataSchemaVersion, model.SchemaVersion)
	}
	if decoded.UUID != crash.UUID {
		t.Errorf("uuid: got %q, want %q", decoded.UUID, crash.UUID)
	}
	if decoded.Error.Kind != model.ErrorKindUnixSignal {
		t.Errorf("error.kind: got %q, want %q", decoded.Error.Kind, model.ErrorKindUnixSignal)
	}
	if decoded.SigInfo.SiSigno != 11 {
		t.Errorf("sig_info.si_signo: got %d, want 11", decoded.SigInfo.SiSigno)
	}
	if decoded.SigInfo.SiCodeHumanReadable != model.CodeSEGV_MAPERR {
		t.Errorf("sig_info.si_code_human_readable: got %q, want %q",
			decoded.SigInfo.SiCodeHumanReadable, model.CodeSEGV_MAPERR)
	}
	if len(decoded.Error.Stack.Frames) != 1 {
		t.Fatalf("stack frames: got %d, want 1", len(decoded.Error.Stack.Frames))
	}
	if decoded.Error.Stack.Frames[0].Function != "strlen" {
		t.Errorf("frame function: got %q, want %q", decoded.Error.Stack.Frames[0].Function, "strlen")
	}
	if decoded.Error.Stack.Format != model.StackTraceFormat {
		t.Errorf("stack format: got %q, want %q", decoded.Error.Stack.Format, model.StackTraceFormat)
	}
}

func TestSignalNameFromNumber(t *testing.T) {
	tests := []struct {
		signo int32
		want  model.SignalName
	}{
		{11, model.SignalSIGSEGV},
		{6, model.SignalSIGABRT},
		{7, model.SignalSIGBUS},
		{8, model.SignalSIGFPE},
		{4, model.SignalSIGILL},
		{9, model.SignalSIGKILL},
		{99, model.SignalUNKNOWN},
	}
	for _, tt := range tests {
		got := model.SignalNameFromNumber(tt.signo)
		if got != tt.want {
			t.Errorf("SignalNameFromNumber(%d) = %q, want %q", tt.signo, got, tt.want)
		}
	}
}

func TestSiCodeName(t *testing.T) {
	tests := []struct {
		signo int32
		code  int32
		want  model.SiCode
	}{
		{11, 1, model.CodeSEGV_MAPERR},
		{11, 2, model.CodeSEGV_ACCERR},
		{7, 1, model.CodeBUS_ADRALN},
		{8, 1, model.CodeFPE_INTDIV},
		{4, 1, model.CodeILL_ILLOPC},
		{11, -6, model.CodeSI_TKILL},
		{11, 99, model.CodeUNKNOWN},
	}
	for _, tt := range tests {
		got := model.SiCodeName(tt.signo, tt.code)
		if got != tt.want {
			t.Errorf("SiCodeName(%d, %d) = %q, want %q", tt.signo, tt.code, got, tt.want)
		}
	}
}

func TestOOMCrashInfo(t *testing.T) {
	crash := model.CrashInfo{
		DataSchemaVersion: model.SchemaVersion,
		Error: model.ErrorData{
			IsCrash:    true,
			Kind:       model.ErrorKindOOMKill,
			Message:    "Process killed by OOM killer (used 512 MB, limit 512 MB)",
			SourceType: "Crashtracking",
		},
		Incomplete: false,
		Metadata: model.Metadata{
			LibraryName:    "dd-ebpf-crashtracker",
			LibraryVersion: "0.1.0",
			Family:         "native",
		},
		OsInfo: model.OsInfo{
			Architecture: "x86_64",
			Bitness:      "64-bit",
			OsType:       "Linux",
			Version:      "6.8.0",
		},
		SigInfo: &model.SigInfo{
			SiSigno:              9,
			SiSignoHumanReadable: model.SignalSIGKILL,
			SiCode:               128,
			SiCodeHumanReadable:  model.CodeSI_KERNEL,
		},
		Experimental: &model.Experimental{
			MemoryInfo: &model.MemoryInfo{
				VmRSSKB:                524288,
				CgroupMemoryLimitBytes: 536870912,
				CgroupMemoryUsageBytes: 536870000,
			},
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		UUID:      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	}

	data, err := json.Marshal(crash)
	if err != nil {
		t.Fatalf("marshal OOM crash: %v", err)
	}

	var decoded model.CrashInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal OOM crash: %v", err)
	}

	if decoded.Error.Kind != model.ErrorKindOOMKill {
		t.Errorf("error.kind: got %q, want %q", decoded.Error.Kind, model.ErrorKindOOMKill)
	}
	if decoded.Experimental.MemoryInfo.CgroupMemoryLimitBytes != 536870912 {
		t.Errorf("memory limit: got %d, want 536870912", decoded.Experimental.MemoryInfo.CgroupMemoryLimitBytes)
	}
}
