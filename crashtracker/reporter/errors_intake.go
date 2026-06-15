package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/dd-otel-host-profiler/crashtracker/config"
	"github.com/DataDog/dd-otel-host-profiler/crashtracker/model"
)

// ErrorsIntakeReporter sends crash reports to the Datadog Errors Intake endpoint.
type ErrorsIntakeReporter struct {
	cfg    *config.Config
	client *http.Client
}

// NewErrorsIntake creates a reporter that sends to the errors intake.
func NewErrorsIntake(cfg *config.Config) *ErrorsIntakeReporter {
	return &ErrorsIntakeReporter{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IntakePayload is the wire format sent to /api/v2/errorsintake (RFC 0013).
type IntakePayload struct {
	Timestamp int64       `json:"timestamp"`
	DDSource  string      `json:"ddsource"`
	DDTags    string      `json:"ddtags"`
	Error     IntakeError `json:"error"`
	OsInfo    model.OsInfo  `json:"os_info"`
	SigInfo   *model.SigInfo `json:"sig_info,omitempty"`
	ProcInfo  *model.ProcInfo `json:"proc_info,omitempty"`
	Ucontext  *model.Ucontext `json:"ucontext,omitempty"`
	Files     map[string][]string `json:"files,omitempty"`
	TraceID   *string `json:"trace_id"`
}

// IntakeError is the error object in the errors intake payload.
type IntakeError struct {
	Type         string              `json:"type"`
	Message      string              `json:"message,omitempty"`
	Stack        *model.StackTrace   `json:"stack,omitempty"`
	Threads      []model.ThreadData  `json:"threads,omitempty"`
	ThreadName   string              `json:"thread_name,omitempty"`
	IsCrash      bool                `json:"is_crash"`
	SourceType   string              `json:"source_type"`
	Experimental *model.Experimental `json:"experimental,omitempty"`
}

// Report serializes and sends a crash report.
func (r *ErrorsIntakeReporter) Report(crash *model.CrashInfo) error {
	payload := r.buildPayload(crash)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	url := r.endpoint()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	r.setHeaders(req)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("errors intake returned %d", resp.StatusCode)
	}
	return nil
}

func (r *ErrorsIntakeReporter) buildPayload(crash *model.CrashInfo) IntakePayload {
	sigName := ""
	if crash.SigInfo != nil {
		sigName = string(crash.SigInfo.SiSignoHumanReadable)
	} else if crash.Error.Kind == model.ErrorKindOOMKill {
		sigName = "OOMKill"
	}

	return IntakePayload{
		Timestamp: parseTimestampMs(crash.Timestamp),
		DDSource:  "crashtracker",
		DDTags:    r.buildTags(crash),
		Error: IntakeError{
			Type:         sigName,
			Message:      crash.Error.Message,
			Stack:        crash.Error.Stack,
			Threads:      crash.Error.Threads,
			ThreadName:   crash.Error.ThreadName,
			IsCrash:      true,
			SourceType:   "Crashtracking",
			Experimental: crash.Experimental,
		},
		OsInfo:   crash.OsInfo,
		SigInfo:  crash.SigInfo,
		ProcInfo: crash.ProcInfo,
		Ucontext: crash.Ucontext,
		Files:    crash.Files,
		TraceID:  nil,
	}
}

func (r *ErrorsIntakeReporter) buildTags(crash *model.CrashInfo) string {
	var tags []string

	// Service tags
	svc := r.cfg.Service
	if svc == "" {
		svc = "unknown"
	}
	tags = append(tags, "service:"+svc)
	if r.cfg.Environment != "" {
		tags = append(tags, "env:"+r.cfg.Environment)
	}
	if r.cfg.Version != "" {
		tags = append(tags, "version:"+r.cfg.Version)
	}

	// Runtime tags
	tags = append(tags, "language_name:native")

	// Crash info tags
	tags = append(tags, "data_schema_version:"+crash.DataSchemaVersion)
	if crash.Fingerprint != "" {
		tags = append(tags, "fingerprint:"+crash.Fingerprint)
	}
	tags = append(tags, fmt.Sprintf("incomplete:%t", crash.Incomplete))
	tags = append(tags, "is_crash:true")
	tags = append(tags, "uuid:"+crash.UUID)

	// Signal tags
	if crash.SigInfo != nil {
		if crash.SigInfo.SiAddr != "" {
			tags = append(tags, "si_addr:"+crash.SigInfo.SiAddr)
		}
		tags = append(tags, fmt.Sprintf("si_code:%d", crash.SigInfo.SiCode))
		tags = append(tags, "si_code_human_readable:"+string(crash.SigInfo.SiCodeHumanReadable))
		tags = append(tags, fmt.Sprintf("si_signo:%d", crash.SigInfo.SiSigno))
		tags = append(tags, "si_signo_human_readable:"+string(crash.SigInfo.SiSignoHumanReadable))
	}

	// Platform + collector tags
	tags = append(tags, "collector:ebpf")

	return strings.Join(tags, ",")
}

func (r *ErrorsIntakeReporter) endpoint() string {
	if r.cfg.APIKey != "" {
		// Direct submission
		site := r.cfg.Site
		if site == "" {
			site = "datadoghq.com"
		}
		return fmt.Sprintf("https://error-tracking-intake.%s/api/v2/errorsintake", site)
	}
	// Agent proxy
	agentURL := strings.TrimRight(r.cfg.AgentURL, "/")
	return agentURL + "/evp_proxy/v4/api/v2/errorsintake"
}

func (r *ErrorsIntakeReporter) setHeaders(req *http.Request) {
	if r.cfg.APIKey != "" {
		req.Header.Set("DD-API-KEY", r.cfg.APIKey)
	} else {
		req.Header.Set("X-Datadog-EVP-Subdomain", "error-tracking-intake")
	}
}

// Close shuts down the reporter.
func (r *ErrorsIntakeReporter) Close() error {
	r.client.CloseIdleConnections()
	return nil
}

func parseTimestampMs(ts string) int64 {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Now().UnixMilli()
	}
	return t.UnixMilli()
}
