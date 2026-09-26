// Package tracelabelguard keeps sensitive values out of goroutine
// tracebacks that carry runtime/pprof labels.
//
// Go 1.27 flipped the runtime's tracebacklabels GODEBUG setting on by
// default (internal/godebugs/table.go: Name: "tracebacklabels", Changed:
// 27, Old: "0"). Before that change, a goroutine label attached with
// runtime/pprof.Do or pprof.WithLabels never showed up in a stack dump.
// After it, every panic, every debug.Stack() call, and every crash dump a
// crash reporter forwards prints the label's key and value inline in the
// goroutine header:
//
//	goroutine 1 [running] {session_token: sk_live_..., user_email: "victim@example.com"}:
//
// pprof labels are a widely recommended place to attach request IDs,
// user IDs and tenant IDs, and in practice people also put tokens,
// passwords and emails there. On a Go 1.27+ toolchain (or any module
// whose go.mod "go" directive is 1.27 or later), that value is now
// printed by default wherever a stack trace is printed.
//
// This package offers two independent things:
//
//   - A runtime guard (Guard, and the package-level Labels/Do/WithLabels
//     wrappers) that redacts label values whose keys match a configurable
//     set of sensitive patterns before the label is ever attached, so the
//     value that reaches runtime/pprof — and therefore any traceback — is
//     "[REDACTED]" instead of the original.
//   - A static scanner (Scan) built on go/ast and go/parser that flags
//     runtime/pprof.Labels call sites with suspicious literal keys or
//     values, and reports whether a module's go.mod puts it on a
//     toolchain where tracebacklabels defaults on.
//
// See the package README for what the redaction and the scanner do not
// catch.
package tracelabelguard
