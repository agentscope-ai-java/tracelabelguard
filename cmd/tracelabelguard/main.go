// Command tracelabelguard scans a Go module for runtime/pprof.Labels
// call sites that attach sensitive-looking values, and reports whether
// the module's go.mod puts it on a toolchain where the tracebacklabels
// GODEBUG setting defaults on (Go 1.27+), which is what makes those
// values print in goroutine tracebacks.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/agentscope-ai-java/tracelabelguard"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("tracelabelguard", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dir          string
		jsonOut      bool
		failOn       string
		includeTests bool
	)
	fs.StringVar(&dir, "dir", ".", "directory to scan")
	fs.BoolVar(&jsonOut, "json", false, "print the full result as JSON instead of the summary")
	fs.StringVar(&failOn, "fail-on", "critical,warning", "comma-separated finding codes or severities that make the exit code 1")
	fs.BoolVar(&includeTests, "include-tests", false, "also scan _test.go files")
	fs.Usage = func() {
		fmt.Fprintf(stderr, `tracelabelguard flags runtime/pprof.Labels call sites with sensitive-looking
keys or values, and reports whether this module defaults tracebacklabels on.

Usage:
  tracelabelguard [flags]

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, `
Exit codes:
  0  ran cleanly, no finding matched --fail-on
  1  a finding matched --fail-on
  2  tracelabelguard itself failed (bad flags, directory unreadable, a .go file failed to parse, ...)

Examples:
  tracelabelguard
  tracelabelguard --dir ./services/api
  tracelabelguard --json
  tracelabelguard --fail-on critical
  tracelabelguard --fail-on sensitive-label-key,sensitive-label-value
`)
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	result, err := tracelabelguard.Scan(tracelabelguard.ScanOptions{
		Dir:          dir,
		IncludeTests: includeTests,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		printSummary(stdout, result)
	}

	var failTokens []string
	if failOn != "" {
		failTokens = strings.Split(failOn, ",")
	}
	if result.FailOn(failTokens) {
		return 1
	}
	return 0
}

var severityOrder = map[tracelabelguard.Severity]int{
	tracelabelguard.SeverityCritical: 0,
	tracelabelguard.SeverityWarning:  1,
	tracelabelguard.SeverityInfo:     2,
}

func printSummary(w *os.File, r *tracelabelguard.ScanResult) {
	fmt.Fprintf(w, "scanned %d file(s) under %s\n", r.FilesScanned, r.Dir)
	if r.GoModPath != "" {
		fmt.Fprintf(w, "go.mod: %s (go %s)\n", r.GoModPath, r.GoDirective)
	}
	fmt.Fprintln(w)

	findings := append([]tracelabelguard.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})

	counts := map[tracelabelguard.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "%d finding(s): %d critical, %d warning, %d info\n\n",
		len(findings), counts[tracelabelguard.SeverityCritical], counts[tracelabelguard.SeverityWarning], counts[tracelabelguard.SeverityInfo])

	for _, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d:%d", f.File, f.Line, f.Col)
		}
		fmt.Fprintf(w, "%-8s %-24s %s\n", strings.ToUpper(string(f.Severity)), f.Code, loc)
		fmt.Fprintf(w, "         %s\n", f.Message)
	}
}
