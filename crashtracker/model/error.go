package model

// ErrorData represents the error section of a crash report.
type ErrorData struct {
	IsCrash      bool          `json:"is_crash"`
	Kind         ErrorKind     `json:"kind"`
	Message      string        `json:"message,omitempty"`
	SourceType   string        `json:"source_type"`
	Stack        *StackTrace   `json:"stack,omitempty"`
	ThreadName   string        `json:"thread_name,omitempty"`
	Threads      []ThreadData  `json:"threads,omitempty"`
	Experimental *Experimental `json:"experimental,omitempty"`
}

// ErrorKind classifies the type of error.
type ErrorKind string

const (
	ErrorKindPanic              ErrorKind = "Panic"
	ErrorKindUnhandledException ErrorKind = "UnhandledException"
	ErrorKindUnixSignal         ErrorKind = "UnixSignal"
	ErrorKindOOMKill            ErrorKind = "OOMKill"
)

// ThreadData describes a non-crashing thread collected at crash time.
type ThreadData struct {
	Crashed bool       `json:"crashed"`
	Name    string     `json:"name"`
	Stack   StackTrace `json:"stack"`
	State   string     `json:"state,omitempty"`
}
