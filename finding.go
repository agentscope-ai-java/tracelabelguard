package tracelabelguard

// Severity classifies how serious a Finding is.
type Severity string

const (
	// SeverityCritical marks a finding that is very likely a real bug or
	// a real leak: a malformed pprof.Labels call that will panic at
	// runtime, for instance.
	SeverityCritical Severity = "critical"
	// SeverityWarning marks a finding worth a human's attention but not
	// certain to be a problem: a literal label key or value that looks
	// sensitive by the heuristics this package uses, which can both miss
	// real leaks and flag innocuous code.
	SeverityWarning Severity = "warning"
	// SeverityInfo marks a finding that is informational only, such as
	// reporting the module's tracebacklabels default.
	SeverityInfo Severity = "info"
)

// Code identifies the kind of Finding, stable across tracelabelguard
// versions, meant for --fail-on and for scripts consuming --json output.
type Code string

const (
	// CodeSensitiveLabelKey marks a pprof.Labels(...) call site whose
	// literal key matches a sensitive pattern.
	CodeSensitiveLabelKey Code = "sensitive-label-key"
	// CodeSensitiveLabelValue marks a call site whose literal value
	// matches a ValueDetector (JWT shape, known secret prefix, ...)
	// even though its key did not match any pattern.
	CodeSensitiveLabelValue Code = "sensitive-label-value"
	// CodeMalformedLabelsCall marks a pprof.Labels(...) call with an odd
	// number of literal arguments where the scanner could otherwise
	// fully enumerate the argument list: that call panics at runtime.
	CodeMalformedLabelsCall Code = "malformed-labels-call"
	// CodeTracebackLabelsDefaultOn is an informational finding: the
	// module's go.mod "go" directive is 1.27 or later, so the
	// tracebacklabels GODEBUG setting defaults on and pprof labels are
	// printed in goroutine tracebacks unless overridden.
	CodeTracebackLabelsDefaultOn Code = "tracebacklabels-default-on"
	// CodeTracebackLabelsDefaultOff is the informational counterpart:
	// the go.mod "go" directive predates 1.27, so tracebacklabels
	// defaults off even when built with a 1.27+ toolchain.
	CodeTracebackLabelsDefaultOff Code = "tracebacklabels-default-off"
	// CodeGoVersionUnknown is informational: no go.mod was found (or its
	// "go" directive could not be parsed), so the scanner cannot say
	// which tracebacklabels default applies.
	CodeGoVersionUnknown Code = "go-version-unknown"
)

// Finding is one thing Scan noticed about a source file or a module's
// go.mod.
type Finding struct {
	Code     Code     `json:"code"`
	Severity Severity `json:"severity"`
	// File is the path Scan was given to reach the file, relative to the
	// scanned directory when the directory itself was relative.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Col  int    `json:"col,omitempty"`
	// Key is the literal label key involved, when applicable.
	Key string `json:"key,omitempty"`
	// Message is a one-line, human-readable statement of what was found.
	Message string `json:"message"`
}
