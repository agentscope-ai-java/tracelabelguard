package tracelabelguard

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const sourceWithLeak = `package app

import (
	"context"
	"runtime/pprof"
)

func handle(ctx context.Context, token, email string) {
	pprof.Do(ctx, pprof.Labels(
		"session_token", token,
		"user_email", "victim@example.com",
		"request_id", "req-1",
	), func(ctx context.Context) {})
}
`

const sourceClean = `package app

import (
	"context"
	"runtime/pprof"
)

func handle(ctx context.Context, id string) {
	pprof.Do(ctx, pprof.Labels(
		"request_id", id,
		"tenant", "acme",
	), func(ctx context.Context) {})
}
`

const sourceMalformed = `package app

import "runtime/pprof"

func bad() {
	pprof.Labels("only_a_key")
}
`

const sourceAliasedImport = `package app

import (
	pp "runtime/pprof"
)

func handle() {
	pp.Labels("password", "hunter2")
}
`

const sourceDotImport = `package app

import (
	. "runtime/pprof"
)

func handle() {
	Labels("password", "hunter2")
}
`

func TestScanFindsSensitiveLiteralKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.27.1\n")
	writeFile(t, dir, "app.go", sourceWithLeak)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if !res.GoDirectiveKnown || !res.TracebackLabelsDefaultOn {
		t.Errorf("expected go 1.27.1 to be recognized with tracebacklabels default ON, got known=%v on=%v", res.GoDirectiveKnown, res.TracebackLabelsDefaultOn)
	}

	var gotKeyFinding bool
	for _, f := range res.Findings {
		if f.Code == CodeSensitiveLabelKey && f.Key == "user_email" {
			gotKeyFinding = true
			if f.Severity != SeverityWarning {
				t.Errorf("severity = %v, want warning", f.Severity)
			}
			if f.Line == 0 {
				t.Errorf("expected a non-zero line number")
			}
		}
	}
	if !gotKeyFinding {
		t.Errorf("expected a sensitive-label-key finding for %q, findings: %+v", "user_email", res.Findings)
	}

	// The non-literal token value (a variable) must not produce a
	// spurious value-shape finding since the scanner can't evaluate it,
	// but its key isn't sensitive-pattern-literal either... actually
	// "session_token" the key itself is a literal and should also be
	// flagged.
	var gotSessionToken bool
	for _, f := range res.Findings {
		if f.Code == CodeSensitiveLabelKey && f.Key == "session_token" {
			gotSessionToken = true
		}
	}
	if !gotSessionToken {
		t.Errorf("expected a sensitive-label-key finding for %q", "session_token")
	}
}

func TestScanCleanSourceProducesNoLabelFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.24.0\n")
	writeFile(t, dir, "app.go", sourceClean)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.GoDirectiveKnown && res.TracebackLabelsDefaultOn {
		t.Errorf("go 1.24.0 should NOT default tracebacklabels on")
	}
	for _, f := range res.Findings {
		if f.Code == CodeSensitiveLabelKey || f.Code == CodeSensitiveLabelValue || f.Code == CodeMalformedLabelsCall {
			t.Errorf("unexpected finding on clean source: %+v", f)
		}
	}
}

func TestScanFindsMalformedCall(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.27\n")
	writeFile(t, dir, "app.go", sourceMalformed)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var got bool
	for _, f := range res.Findings {
		if f.Code == CodeMalformedLabelsCall {
			got = true
			if f.Severity != SeverityCritical {
				t.Errorf("severity = %v, want critical", f.Severity)
			}
		}
	}
	if !got {
		t.Errorf("expected a malformed-labels-call finding, findings: %+v", res.Findings)
	}
}

func TestScanHandlesAliasedAndDotImports(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.27\n")
	writeFile(t, dir, "aliased/app.go", sourceAliasedImport)
	writeFile(t, dir, "dot/app.go", sourceDotImport)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := map[string]bool{}
	for _, f := range res.Findings {
		if f.Code == CodeSensitiveLabelKey {
			found[f.File] = true
		}
	}
	if !found[filepath.Join(dir, "aliased/app.go")] {
		t.Errorf("expected a finding for the aliased-import file, findings: %+v", res.Findings)
	}
	if !found[filepath.Join(dir, "dot/app.go")] {
		t.Errorf("expected a finding for the dot-import file, findings: %+v", res.Findings)
	}
}

func TestScanNoGoMod(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.go", sourceClean)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.GoDirectiveKnown {
		t.Errorf("expected GoDirectiveKnown = false with no go.mod")
	}
	var gotUnknown bool
	for _, f := range res.Findings {
		if f.Code == CodeGoVersionUnknown {
			gotUnknown = true
		}
	}
	if !gotUnknown {
		t.Errorf("expected a go-version-unknown finding")
	}
}

func TestScanSkipsTestFilesByDefault(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.27\n")
	writeFile(t, dir, "app_test.go", sourceWithLeak)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.FilesScanned != 0 {
		t.Errorf("FilesScanned = %d, want 0 (test files skipped by default)", res.FilesScanned)
	}

	res2, err := Scan(ScanOptions{Dir: dir, IncludeTests: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res2.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1 with IncludeTests", res2.FilesScanned)
	}
}

func TestScanResultFailOn(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.27.1\n")
	writeFile(t, dir, "app.go", sourceWithLeak)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.FailOn([]string{"warning"}) {
		t.Errorf("expected FailOn([warning]) = true")
	}
	if res.FailOn([]string{"critical"}) {
		t.Errorf("expected FailOn([critical]) = false, no malformed call here")
	}
	if res.FailOn(nil) {
		t.Errorf("expected FailOn(nil) = false")
	}
}

func TestScanSkipsVendor(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.27\n")
	writeFile(t, dir, "vendor/thirdparty/lib.go", sourceWithLeak)
	writeFile(t, dir, "app.go", sourceClean)

	res, err := Scan(ScanOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1 (vendor/ skipped)", res.FilesScanned)
	}
}

func TestScanUnreadableDirectory(t *testing.T) {
	_, err := Scan(ScanOptions{Dir: filepath.Join(t.TempDir(), "does-not-exist")})
	if err == nil {
		t.Fatal("expected an error scanning a nonexistent directory")
	}
}
