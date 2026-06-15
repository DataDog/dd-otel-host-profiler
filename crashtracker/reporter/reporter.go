package reporter

import (
	"github.com/DataDog/dd-otel-host-profiler/crashtracker/model"
)

// Reporter defines the interface for crash report delivery.
type Reporter interface {
	// Report sends a crash report to the backend.
	Report(crash *model.CrashInfo) error

	// Close gracefully shuts down the reporter.
	Close() error
}
