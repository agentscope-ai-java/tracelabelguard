package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runCLI(t *testing.T, args []string) (stdout, stderr string, code int) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	code = run(args, outW, errW)
	outW.Close()
	errW.Close()

	outBuf := make([]byte, 1<<20)
	n, _ := outR.Read(outBuf)
	stdout = string(outBuf[:n])

	errBuf := make([]byte, 1<<20)
	n, _ = errR.Read(errBuf)
	stderr = string(errBuf[:n])

	return stdout, stderr, code
}

const leakySource = `package app

import "runtime/pprof"

func handle() {
	pprof.Labels("session_token", "sk_live_abc123")
}
`

const cleanSource = `package app

import "runtime/pprof"

func handle() {
	pprof.Labels("request_id", "req-1")
}
`

func TestRun_CleanModuleExitsZero(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.24.0\n")
	mustWrite(t, filepath.Join(dir, "app.go"), cleanSource)

	stdout, _, code := runCLI(t, []string{"--dir", dir})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "0 critical, 0 warning") {
		t.Errorf("expected zero critical/warning findings:\n%s", stdout)
	}
}

func TestRun_LeakyModuleExitsOne(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.27.1\n")
	mustWrite(t, filepath.Join(dir, "app.go"), leakySource)

	stdout, _, code := runCLI(t, []string{"--dir", dir})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (default --fail-on is critical,warning)\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "sensitive-label-key") {
		t.Errorf("stdout should mention sensitive-label-key:\n%s", stdout)
	}
	if !strings.Contains(stdout, "tracebacklabels-default-on") {
		t.Errorf("stdout should report the go 1.27.1 tracebacklabels default:\n%s", stdout)
	}
}

func TestRun_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.27\n")
	mustWrite(t, filepath.Join(dir, "app.go"), leakySource)

	stdout, _, code := runCLI(t, []string{"--dir", dir, "--json"})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}
	if _, ok := parsed["findings"]; !ok {
		t.Errorf("JSON missing 'findings' key: %s", stdout)
	}
}

func TestRun_FailOnOverride(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.27\n")
	mustWrite(t, filepath.Join(dir, "app.go"), leakySource)

	_, _, code := runCLI(t, []string{"--dir", dir, "--fail-on", "critical"})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: no malformed-labels-call (critical) finding here, only a warning", code)
	}
}

func TestRun_BadFlagExitsTwo(t *testing.T) {
	_, _, code := runCLI(t, []string{"--not-a-real-flag"})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_NonexistentDirExitsTwo(t *testing.T) {
	_, _, code := runCLI(t, []string{"--dir", filepath.Join(t.TempDir(), "nope")})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_UnparseableGoFileExitsTwo(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.27\n")
	mustWrite(t, filepath.Join(dir, "broken.go"), "package app\n\nfunc broken( {\n")

	_, stderr, code := runCLI(t, []string{"--dir", dir})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\nstderr: %s", code, stderr)
	}
}

func TestRun_NoGoModIsInfoNotError(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "app.go"), cleanSource)

	stdout, _, code := runCLI(t, []string{"--dir", dir})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (missing go.mod is informational only)\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "go-version-unknown") {
		t.Errorf("expected a go-version-unknown info finding:\n%s", stdout)
	}
}
