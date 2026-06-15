package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadFromEnv(t *testing.T) {
	// Set up env vars
	envs := map[string]string{
		"DD_CRASHTRACKER_SIGNALS":               "SIGSEGV,SIGABRT",
		"DD_CRASHTRACKER_EXCLUDE_EXECUTABLES":   "/usr/lib/jvm/*,/usr/bin/go",
		"DD_CRASHTRACKER_MAX_CRASHES_PER_MINUTE": "50",
		"DD_CRASHTRACKER_DEDUP_WINDOW":          "30s",
		"DD_CRASHTRACKER_USE_CORE_HANDLER":      "false",
		"DD_CRASHTRACKER_CORE_HANDLER_TIMEOUT":  "15s",
		"DD_CRASHTRACKER_CORE_HANDLER_COEXIST_MODE": "fallback",
		"DD_TRACE_AGENT_URL":                    "http://agent:8126",
		"DD_API_KEY":                            "test-key-123",
		"DD_SITE":                               "datadoghq.eu",
		"DD_ENV":                                "staging",
		"DD_SERVICE":                            "myservice",
		"DD_VERSION":                            "1.2.3",
		"DD_TAGS":                               "team:backend,region:eu",
		"DD_CRASHTRACKER_VERBOSE":               "true",
		"DD_CRASHTRACKER_COLLECT_ALL_THREADS":   "false",
		"DD_CRASHTRACKER_MAX_THREADS":           "128",
	}

	for k, v := range envs {
		os.Setenv(k, v)
	}
	defer func() {
		for k := range envs {
			os.Unsetenv(k)
		}
	}()

	cfg := DefaultConfig()
	cfg.LoadFromEnv()

	if len(cfg.Signals) != 2 || cfg.Signals[0] != "SIGSEGV" || cfg.Signals[1] != "SIGABRT" {
		t.Errorf("Signals = %v, want [SIGSEGV SIGABRT]", cfg.Signals)
	}
	if len(cfg.ExcludeExecutables) != 2 {
		t.Errorf("ExcludeExecutables = %v, want 2 entries", cfg.ExcludeExecutables)
	}
	if cfg.MaxCrashesPerMinute != 50 {
		t.Errorf("MaxCrashesPerMinute = %d, want 50", cfg.MaxCrashesPerMinute)
	}
	if cfg.DedupWindow != 30*time.Second {
		t.Errorf("DedupWindow = %v, want 30s", cfg.DedupWindow)
	}
	if cfg.UseCoreHandler != false {
		t.Errorf("UseCoreHandler = %v, want false", cfg.UseCoreHandler)
	}
	if cfg.CoreHandlerTimeout != 15*time.Second {
		t.Errorf("CoreHandlerTimeout = %v, want 15s", cfg.CoreHandlerTimeout)
	}
	if cfg.CoreHandlerCoexist != "fallback" {
		t.Errorf("CoreHandlerCoexist = %q, want fallback", cfg.CoreHandlerCoexist)
	}
	if cfg.AgentURL != "http://agent:8126" {
		t.Errorf("AgentURL = %q, want http://agent:8126", cfg.AgentURL)
	}
	if cfg.APIKey != "test-key-123" {
		t.Errorf("APIKey = %q, want test-key-123", cfg.APIKey)
	}
	if cfg.Site != "datadoghq.eu" {
		t.Errorf("Site = %q, want datadoghq.eu", cfg.Site)
	}
	if cfg.Environment != "staging" {
		t.Errorf("Environment = %q, want staging", cfg.Environment)
	}
	if cfg.Service != "myservice" {
		t.Errorf("Service = %q, want myservice", cfg.Service)
	}
	if cfg.Version != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3", cfg.Version)
	}
	if len(cfg.Tags) != 2 || cfg.Tags[0] != "team:backend" || cfg.Tags[1] != "region:eu" {
		t.Errorf("Tags = %v, want [team:backend region:eu]", cfg.Tags)
	}
	if cfg.Verbose != true {
		t.Errorf("Verbose = %v, want true", cfg.Verbose)
	}
	if cfg.CollectAllThreads != false {
		t.Errorf("CollectAllThreads = %v, want false", cfg.CollectAllThreads)
	}
	if cfg.MaxThreads != 128 {
		t.Errorf("MaxThreads = %d, want 128", cfg.MaxThreads)
	}
}

func TestLoadFromEnvDefaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LoadFromEnv()

	if cfg.AgentURL != "http://localhost:8126" {
		t.Errorf("AgentURL should keep default when env not set, got %q", cfg.AgentURL)
	}
	if cfg.MaxCrashesPerMinute != 100 {
		t.Errorf("MaxCrashesPerMinute should keep default when env not set, got %d", cfg.MaxCrashesPerMinute)
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"Yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
		{"anything", false},
	}

	for _, tt := range tests {
		got := parseBool(tt.input)
		if got != tt.want {
			t.Errorf("parseBool(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
