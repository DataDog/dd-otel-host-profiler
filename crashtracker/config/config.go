package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration for the eBPF crash tracker daemon.
type Config struct {
	// Collection
	Signals []string `json:"signals"`

	// Filtering
	ExcludeExecutables []string `json:"exclude_executables"`

	// Rate limiting
	MaxCrashesPerMinute int           `json:"max_crashes_per_minute"`
	DedupWindow         time.Duration `json:"dedup_window"`

	// Core handler
	UseCoreHandler     bool          `json:"use_core_handler"`
	CoreHandlerTimeout time.Duration `json:"core_handler_timeout"`
	CoreHandlerPath    string        `json:"core_handler_path"`
	CoreHandlerCoexist string        `json:"core_handler_coexist_mode"`

	// Reporting (matches RFC 0013 config vars)
	AgentURL    string   `json:"agent_url"`
	APIKey      string   `json:"api_key"`
	Site        string   `json:"site"`
	Environment string   `json:"environment"`
	Service     string   `json:"service"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`

	// Symbolication
	SymbolicateLocally bool `json:"symbolicate_locally"`
	UploadSymbols      bool `json:"upload_symbols"`
	MaxSymbolCacheMB   int  `json:"max_symbol_cache_mb"`

	// Thread collection
	CollectAllThreads       bool          `json:"collect_all_threads"`
	MaxThreads              int           `json:"max_threads"`
	ThreadCollectionTimeout time.Duration `json:"thread_collection_timeout"`

	// Debug
	Verbose        bool   `json:"verbose"`
	LocalOutputDir string `json:"local_output_dir"`

	// Socket path for core handler communication
	SocketPath string `json:"socket_path"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Signals:                 []string{"SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGTRAP"},
		MaxCrashesPerMinute:     100,
		DedupWindow:             60 * time.Second,
		UseCoreHandler:          true,
		CoreHandlerTimeout:      30 * time.Second,
		CoreHandlerPath:         "/usr/lib/crashtracker/core-handler",
		CoreHandlerCoexist:      "chain",
		AgentURL:                "http://localhost:8126",
		Site:                    "datadoghq.com",
		SymbolicateLocally:      true,
		UploadSymbols:           true,
		MaxSymbolCacheMB:        256,
		CollectAllThreads:       true,
		MaxThreads:              256,
		ThreadCollectionTimeout: 10 * time.Second,
		SocketPath:              "/run/crashtracker.sock",
	}
}

// LoadFromEnv populates a Config from environment variables.
// Only fields with a corresponding env var set are overwritten;
// start from DefaultConfig() for sensible defaults.
func (c *Config) LoadFromEnv() {
	if v := os.Getenv("DD_CRASHTRACKER_SIGNALS"); v != "" {
		c.Signals = splitComma(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_EXCLUDE_EXECUTABLES"); v != "" {
		c.ExcludeExecutables = splitComma(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_MAX_CRASHES_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxCrashesPerMinute = n
		}
	}
	if v := os.Getenv("DD_CRASHTRACKER_DEDUP_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.DedupWindow = d
		}
	}
	if v := os.Getenv("DD_CRASHTRACKER_USE_CORE_HANDLER"); v != "" {
		c.UseCoreHandler = parseBool(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_CORE_HANDLER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.CoreHandlerTimeout = d
		}
	}
	if v := os.Getenv("DD_CRASHTRACKER_CORE_HANDLER_PATH"); v != "" {
		c.CoreHandlerPath = v
	}
	if v := os.Getenv("DD_CRASHTRACKER_CORE_HANDLER_COEXIST_MODE"); v != "" {
		c.CoreHandlerCoexist = v
	}
	if v := os.Getenv("DD_TRACE_AGENT_URL"); v != "" {
		c.AgentURL = v
	}
	if v := os.Getenv("DD_API_KEY"); v != "" {
		c.APIKey = v
	}
	if v := os.Getenv("DD_SITE"); v != "" {
		c.Site = v
	}
	if v := os.Getenv("DD_ENV"); v != "" {
		c.Environment = v
	}
	if v := os.Getenv("DD_SERVICE"); v != "" {
		c.Service = v
	}
	if v := os.Getenv("DD_VERSION"); v != "" {
		c.Version = v
	}
	if v := os.Getenv("DD_TAGS"); v != "" {
		c.Tags = splitComma(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_SYMBOLICATE_LOCALLY"); v != "" {
		c.SymbolicateLocally = parseBool(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_UPLOAD_SYMBOLS"); v != "" {
		c.UploadSymbols = parseBool(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_MAX_SYMBOL_CACHE_MB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxSymbolCacheMB = n
		}
	}
	if v := os.Getenv("DD_CRASHTRACKER_COLLECT_ALL_THREADS"); v != "" {
		c.CollectAllThreads = parseBool(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_MAX_THREADS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxThreads = n
		}
	}
	if v := os.Getenv("DD_CRASHTRACKER_THREAD_COLLECTION_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.ThreadCollectionTimeout = d
		}
	}
	if v := os.Getenv("DD_CRASHTRACKER_VERBOSE"); v != "" {
		c.Verbose = parseBool(v)
	}
	if v := os.Getenv("DD_CRASHTRACKER_LOCAL_OUTPUT_DIR"); v != "" {
		c.LocalOutputDir = v
	}
	if v := os.Getenv("DD_CRASHTRACKER_SOCKET_PATH"); v != "" {
		c.SocketPath = v
	}
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}
