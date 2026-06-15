package model

// StackTrace represents an ordered collection of stack frames.
type StackTrace struct {
	Format     string       `json:"format"`
	Frames     []StackFrame `json:"frames"`
	Incomplete bool         `json:"incomplete"`
}

const StackTraceFormat = "Datadog Crashtracker 1.0"

// StackFrame represents a single frame in a stack trace.
// All fields are optional; a frame includes whichever were resolved.
type StackFrame struct {
	// Absolute addresses
	IP                string `json:"ip,omitempty"`
	SP                string `json:"sp,omitempty"`
	SymbolAddress     string `json:"symbol_address,omitempty"`
	ModuleBaseAddress string `json:"module_base_address,omitempty"`

	// Relative addresses (for backend symbolication)
	BuildID         string      `json:"build_id,omitempty"`
	BuildIDType     BuildIDType `json:"build_id_type,omitempty"`
	FileType        FileType    `json:"file_type,omitempty"`
	RelativeAddress string      `json:"relative_address,omitempty"`
	Path            string      `json:"path,omitempty"`

	// Debug information
	Function   string   `json:"function,omitempty"`
	MangledName string  `json:"mangled_name,omitempty"`
	TypeName   string   `json:"type_name,omitempty"`
	File       string   `json:"file,omitempty"`
	Line       uint32   `json:"line,omitempty"`
	Column     uint32   `json:"column,omitempty"`
	Comments   []string `json:"comments,omitempty"`
}

// BuildIDType identifies the format of a build ID.
type BuildIDType string

const (
	BuildIDGNU  BuildIDType = "GNU"
	BuildIDGo   BuildIDType = "GO"
	BuildIDPDB  BuildIDType = "PDB"
	BuildIDSHA1 BuildIDType = "SHA1"
	BuildIDPE   BuildIDType = "PE"
)

// FileType identifies the binary file format.
type FileType string

const (
	FileTypeELF FileType = "ELF"
	FileTypePE  FileType = "PE"
	FileTypeAPK FileType = "APK"
)
