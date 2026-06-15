package model

import "fmt"

// SigInfo contains information from the siginfo_t structure.
type SigInfo struct {
	SiSigno             int32      `json:"si_signo"`
	SiSignoHumanReadable SignalName `json:"si_signo_human_readable"`
	SiCode              int32      `json:"si_code"`
	SiCodeHumanReadable SiCode     `json:"si_code_human_readable"`
	SiAddr              string     `json:"si_addr,omitempty"`
}

// SignalName is a human-readable signal name.
type SignalName string

const (
	SignalSIGHUP   SignalName = "SIGHUP"
	SignalSIGINT   SignalName = "SIGINT"
	SignalSIGQUIT  SignalName = "SIGQUIT"
	SignalSIGILL   SignalName = "SIGILL"
	SignalSIGTRAP  SignalName = "SIGTRAP"
	SignalSIGABRT  SignalName = "SIGABRT"
	SignalSIGBUS   SignalName = "SIGBUS"
	SignalSIGFPE   SignalName = "SIGFPE"
	SignalSIGKILL  SignalName = "SIGKILL"
	SignalSIGSEGV  SignalName = "SIGSEGV"
	SignalSIGPIPE  SignalName = "SIGPIPE"
	SignalSIGALRM  SignalName = "SIGALRM"
	SignalSIGTERM  SignalName = "SIGTERM"
	SignalSIGCHLD  SignalName = "SIGCHLD"
	SignalSIGSYS   SignalName = "SIGSYS"
	SignalUNKNOWN  SignalName = "UNKNOWN"
)

// SiCode is a human-readable signal code.
type SiCode string

const (
	// SIGSEGV codes
	CodeSEGV_MAPERR SiCode = "SEGV_MAPERR"
	CodeSEGV_ACCERR SiCode = "SEGV_ACCERR"
	CodeSEGV_BNDERR SiCode = "SEGV_BNDERR"
	CodeSEGV_PKUERR SiCode = "SEGV_PKUERR"

	// SIGBUS codes
	CodeBUS_ADRALN    SiCode = "BUS_ADRALN"
	CodeBUS_ADRERR    SiCode = "BUS_ADRERR"
	CodeBUS_OBJERR    SiCode = "BUS_OBJERR"
	CodeBUS_MCEERR_AR SiCode = "BUS_MCEERR_AR"
	CodeBUS_MCEERR_AO SiCode = "BUS_MCEERR_AO"

	// SIGFPE codes
	CodeFPE_INTDIV SiCode = "FPE_INTDIV"
	CodeFPE_INTOVF SiCode = "FPE_INTOVF"
	CodeFPE_FLTDIV SiCode = "FPE_FLTDIV"
	CodeFPE_FLTOVF SiCode = "FPE_FLTOVF"
	CodeFPE_FLTUND SiCode = "FPE_FLTUND"
	CodeFPE_FLTRES SiCode = "FPE_FLTRES"
	CodeFPE_FLTINV SiCode = "FPE_FLTINV"
	CodeFPE_FLTSUB SiCode = "FPE_FLTSUB"

	// SIGILL codes
	CodeILL_ILLOPC SiCode = "ILL_ILLOPC"
	CodeILL_ILLOPN SiCode = "ILL_ILLOPN"
	CodeILL_ILLADR SiCode = "ILL_ILLADR"
	CodeILL_ILLTRP SiCode = "ILL_ILLTRP"
	CodeILL_PRVOPC SiCode = "ILL_PRVOPC"
	CodeILL_PRVREG SiCode = "ILL_PRVREG"
	CodeILL_COPROC SiCode = "ILL_COPROC"
	CodeILL_BADSTK SiCode = "ILL_BADSTK"

	// General codes
	CodeSI_USER    SiCode = "SI_USER"
	CodeSI_KERNEL  SiCode = "SI_KERNEL"
	CodeSI_QUEUE   SiCode = "SI_QUEUE"
	CodeSI_TIMER   SiCode = "SI_TIMER"
	CodeSI_MESGQ   SiCode = "SI_MESGQ"
	CodeSI_ASYNCIO SiCode = "SI_ASYNCIO"
	CodeSI_SIGIO   SiCode = "SI_SIGIO"
	CodeSI_TKILL   SiCode = "SI_TKILL"
	CodeSYS_SECCOMP SiCode = "SYS_SECCOMP"
	CodeUNKNOWN    SiCode = "UNKNOWN"
)

var signalNames = map[int32]SignalName{
	1:  SignalSIGHUP,
	2:  SignalSIGINT,
	3:  SignalSIGQUIT,
	4:  SignalSIGILL,
	5:  SignalSIGTRAP,
	6:  SignalSIGABRT,
	7:  SignalSIGBUS,
	8:  SignalSIGFPE,
	9:  SignalSIGKILL,
	11: SignalSIGSEGV,
	13: SignalSIGPIPE,
	14: SignalSIGALRM,
	15: SignalSIGTERM,
	17: SignalSIGCHLD,
	31: SignalSIGSYS,
}

// SignalNameFromNumber returns the human-readable name for a signal number.
func SignalNameFromNumber(signo int32) SignalName {
	if name, ok := signalNames[signo]; ok {
		return name
	}
	return SignalUNKNOWN
}

// siCodeNames maps (signal, code) pairs to human-readable code names.
// Negative codes are general (signal-independent).
var siCodeNames = map[int32]map[int32]SiCode{
	0: { // General codes (used when signal-independent)
		0:    CodeSI_USER,
		-1:   CodeSI_QUEUE,
		-2:   CodeSI_TIMER,
		-3:   CodeSI_MESGQ,
		-4:   CodeSI_ASYNCIO,
		-5:   CodeSI_SIGIO,
		-6:   CodeSI_TKILL,
		128:  CodeSI_KERNEL,
	},
	11: { // SIGSEGV
		1: CodeSEGV_MAPERR,
		2: CodeSEGV_ACCERR,
		3: CodeSEGV_BNDERR,
		4: CodeSEGV_PKUERR,
	},
	7: { // SIGBUS
		1: CodeBUS_ADRALN,
		2: CodeBUS_ADRERR,
		3: CodeBUS_OBJERR,
		4: CodeBUS_MCEERR_AR,
		5: CodeBUS_MCEERR_AO,
	},
	8: { // SIGFPE
		1: CodeFPE_INTDIV,
		2: CodeFPE_INTOVF,
		3: CodeFPE_FLTDIV,
		4: CodeFPE_FLTOVF,
		5: CodeFPE_FLTUND,
		6: CodeFPE_FLTRES,
		7: CodeFPE_FLTINV,
		8: CodeFPE_FLTSUB,
	},
	4: { // SIGILL
		1: CodeILL_ILLOPC,
		2: CodeILL_ILLOPN,
		3: CodeILL_ILLADR,
		4: CodeILL_ILLTRP,
		5: CodeILL_PRVOPC,
		6: CodeILL_PRVREG,
		7: CodeILL_COPROC,
		8: CodeILL_BADSTK,
	},
}

// SiCodeName returns the human-readable name for a signal code.
func SiCodeName(signo, code int32) SiCode {
	// Check signal-specific codes first
	if codes, ok := siCodeNames[signo]; ok {
		if name, ok := codes[code]; ok {
			return name
		}
	}
	// Check general (signal-independent) codes
	if codes, ok := siCodeNames[0]; ok {
		if name, ok := codes[code]; ok {
			return name
		}
	}
	return CodeUNKNOWN
}

// FormatAddress formats an address as a zero-padded hex string.
func FormatAddress(addr uint64) string {
	return fmt.Sprintf("0x%016x", addr)
}
