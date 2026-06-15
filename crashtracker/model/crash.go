package model

// CrashInfo represents a complete crash report following the RFC 0011 v1.8 schema.
// This is the internal representation; it gets serialized to the errors intake
// wire format (RFC 0013) by the reporter package.
type CrashInfo struct {
	Counters          map[string]int64 `json:"counters,omitempty"`
	DataSchemaVersion string           `json:"data_schema_version"`
	Error             ErrorData        `json:"error"`
	Experimental      *Experimental    `json:"experimental,omitempty"`
	Files             map[string][]string `json:"files,omitempty"`
	Fingerprint       string           `json:"fingerprint,omitempty"`
	Incomplete        bool             `json:"incomplete"`
	LogMessages       []string         `json:"log_messages,omitempty"`
	Metadata          Metadata         `json:"metadata"`
	OsInfo            OsInfo           `json:"os_info"`
	ProcInfo          *ProcInfo        `json:"proc_info,omitempty"`
	SigInfo           *SigInfo         `json:"sig_info,omitempty"`
	SpanIDs           []SpanRef        `json:"span_ids,omitempty"`
	Timestamp         string           `json:"timestamp"`
	TraceIDs          []SpanRef        `json:"trace_ids,omitempty"`
	Ucontext          *Ucontext        `json:"ucontext,omitempty"`
	UUID              string           `json:"uuid"`
}

const SchemaVersion = "1.8"
