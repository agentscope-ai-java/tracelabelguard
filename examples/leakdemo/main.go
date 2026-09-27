// Command leakdemo prints the exact difference tracelabelguard makes to
// a goroutine traceback that carries pprof labels: the raw,
// unprotected pprof.Labels call versus the same call routed through
// tracelabelguard.Do. Both stacks are captured with the real
// runtime/debug.Stack(), not synthesized.
//
// Run it with:
//
//	go run ./examples/leakdemo
//
// On Go 1.27+ (where tracebacklabels defaults on), the "leaked" section
// below shows the session token and email inline in the goroutine
// header; the "redacted" section, built from the identical values
// through tracelabelguard, does not.
package main

import (
	"context"
	"fmt"
	"runtime/debug"
	"runtime/pprof"
	"strings"

	"github.com/agentscope-ai-java/tracelabelguard"
)

// kvs is the exact label payload used in both runs, so the only
// difference between "leaked" and "redacted" below is which of these two
// call sites attached it.
var kvs = []string{
	"session_token", "sk_live_SUPER_SECRET_TOKEN_12345",
	"user_email", "victim@example.com",
	"request_id", "req-8f3c2a",
}

func main() {
	leaked := captureViaRawPprof()
	redacted := captureViaGuard()

	fmt.Println("=== leaked: raw pprof.Labels / pprof.Do ===")
	fmt.Println(firstLine(leaked))
	fmt.Println()
	fmt.Println("=== redacted: same values through tracelabelguard.Do ===")
	fmt.Println(firstLine(redacted))
	fmt.Println()
	fmt.Println("=== full redacted goroutine dump ===")
	fmt.Println(redacted)
}

// captureViaRawPprof attaches kvs with the unprotected runtime/pprof
// API and returns the real stack trace captured from inside that
// labeled scope.
func captureViaRawPprof() string {
	var stack string
	pprof.Do(context.Background(), pprof.Labels(kvs...), func(ctx context.Context) {
		stack = string(debug.Stack())
	})
	return stack
}

// captureViaGuard attaches the identical kvs through
// tracelabelguard.Do and returns the real stack trace captured from
// inside that labeled scope.
func captureViaGuard() string {
	var stack string
	tracelabelguard.Do(context.Background(), kvs, func(ctx context.Context) {
		stack = string(debug.Stack())
	})
	return stack
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
