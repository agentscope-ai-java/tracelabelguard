package tracelabelguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const pprofImportPath = "runtime/pprof"

// skipDirNames are directory names Scan never descends into, regardless
// of ScanOptions.SkipDirs.
var skipDirNames = map[string]bool{
	"vendor":       true,
	".git":         true,
	"node_modules": true,
}

// ScanOptions controls Scan.
type ScanOptions struct {
	// Dir is the root directory to scan. Defaults to "." when empty.
	Dir string
	// Guard supplies the KeyPatterns and ValueDetectors used to judge
	// literal label keys and values found at pprof.Labels call sites.
	// Defaults to NewGuard()'s settings when nil.
	Guard *Guard
	// SkipDirs names additional directories (by base name, anywhere in
	// the tree) Scan should not descend into, beyond vendor/.git/
	// node_modules, which are always skipped.
	SkipDirs []string
	// IncludeTests, when false (the default), skips *_test.go files.
	IncludeTests bool
}

// ScanResult is the outcome of one Scan.
type ScanResult struct {
	// Dir is the directory that was scanned.
	Dir string `json:"dir"`
	// FilesScanned is the number of .go files Scan actually parsed.
	FilesScanned int `json:"filesScanned"`
	// GoModPath is the go.mod Scan read to determine the tracebacklabels
	// default, or "" if none was found directly under Dir.
	GoModPath string `json:"goModPath,omitempty"`
	// GoDirective is the raw value of go.mod's "go" line (e.g.
	// "1.27.1"), or "" if no go.mod / no directive was found.
	GoDirective string `json:"goDirective,omitempty"`
	// TracebackLabelsDefaultOn reports whether, per GoDirective,
	// tracebacklabels is on by default for this module. Meaningful only
	// when GoDirectiveKnown is true.
	TracebackLabelsDefaultOn bool `json:"tracebackLabelsDefaultOn"`
	// GoDirectiveKnown is false when Scan could not determine
	// TracebackLabelsDefaultOn (no go.mod, or an unparseable directive).
	GoDirectiveKnown bool `json:"goDirectiveKnown"`
	// Findings holds every Finding Scan produced, across every file plus
	// the one informational go.mod finding.
	Findings []Finding `json:"findings"`
}

// FailOn reports whether any Finding in r matches one of the given
// tokens, compared case-insensitively against both the Finding's Code
// and its Severity. An empty tokens list reports false.
func (r *ScanResult) FailOn(tokens []string) bool {
	if r == nil || len(tokens) == 0 {
		return false
	}
	set := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			set[t] = true
		}
	}
	for _, f := range r.Findings {
		if set[strings.ToLower(string(f.Code))] || set[strings.ToLower(string(f.Severity))] {
			return true
		}
	}
	return false
}

// Scan walks the directory tree rooted at opts.Dir, parses every .go
// file with go/parser, and flags runtime/pprof.Labels call sites whose
// literal keys or values look sensitive. It also reads go.mod directly
// under opts.Dir (if present) and reports whether the module's "go"
// directive puts it on a toolchain where the tracebacklabels GODEBUG
// setting defaults on.
//
// Scan only sees what a parser sees: label keys or values built from
// anything other than a string literal (a variable, a constant defined
// elsewhere, a function call, string concatenation) cannot be evaluated
// and are silently skipped, not flagged. See the package README for the
// full list of what this does and does not catch.
func Scan(opts ScanOptions) (*ScanResult, error) {
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	guard := opts.Guard
	if guard == nil {
		guard = NewGuard()
	}
	skip := map[string]bool{}
	for k, v := range skipDirNames {
		skip[k] = v
	}
	for _, d := range opts.SkipDirs {
		skip[d] = true
	}

	result := &ScanResult{Dir: dir}

	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base != "." && (skip[base] || (strings.HasPrefix(base, ".") && base != ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !opts.IncludeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}

		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", path, rerr)
		}
		file, perr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parsing %s: %w", path, perr)
		}
		result.FilesScanned++
		result.Findings = append(result.Findings, scanFile(fset, path, file, guard)...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("tracelabelguard: scanning %s: %w", dir, err)
	}

	if modPath, directive, ok := readGoDirective(dir); ok {
		result.GoModPath = modPath
		result.GoDirective = directive
		defaultOn, known := tracebacklabelsDefault(directive)
		result.GoDirectiveKnown = known
		result.TracebackLabelsDefaultOn = defaultOn
		result.Findings = append(result.Findings, goDirectiveFinding(modPath, directive, defaultOn, known))
	} else {
		result.Findings = append(result.Findings, Finding{
			Code:     CodeGoVersionUnknown,
			Severity: SeverityInfo,
			File:     filepath.Join(dir, "go.mod"),
			Message:  "no go.mod found directly under the scanned directory; cannot determine the tracebacklabels default",
		})
	}

	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Col < b.Col
	})

	return result, nil
}

func goDirectiveFinding(modPath, directive string, defaultOn, known bool) Finding {
	if !known {
		return Finding{
			Code:     CodeGoVersionUnknown,
			Severity: SeverityInfo,
			File:     modPath,
			Message:  fmt.Sprintf("go.mod \"go\" directive %q could not be parsed as a Go version", directive),
		}
	}
	if defaultOn {
		return Finding{
			Code:     CodeTracebackLabelsDefaultOn,
			Severity: SeverityInfo,
			File:     modPath,
			Message: fmt.Sprintf(
				"go.mod declares \"go %s\": tracebacklabels defaults ON, pprof label values print in goroutine tracebacks unless GODEBUG=tracebacklabels=0",
				directive),
		}
	}
	return Finding{
		Code:     CodeTracebackLabelsDefaultOff,
		Severity: SeverityInfo,
		File:     modPath,
		Message: fmt.Sprintf(
			"go.mod declares \"go %s\": tracebacklabels defaults off, pprof label values do not print in goroutine tracebacks unless GODEBUG=tracebacklabels=1",
			directive),
	}
}

// readGoDirective reads go.mod directly under dir and returns its path
// and "go" directive value. ok is false if dir has no go.mod or the file
// has no "go" directive.
func readGoDirective(dir string) (modPath, directive string, ok bool) {
	modPath = filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		return "", "", false
	}
	directive = parseGoDirective(data)
	if directive == "" {
		return modPath, "", false
	}
	return modPath, directive, true
}

// pprofAlias reports the local name file's imports use to refer to
// runtime/pprof: the package identifier calls must be qualified with
// (e.g. "pprof" or a rename), or "" with dot true if the package was
// dot-imported, in which case Labels/Do/WithLabels calls are unqualified
// identifiers instead of selector expressions.
func pprofAlias(file *ast.File) (alias string, dot bool, imported bool) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != pprofImportPath {
			continue
		}
		imported = true
		switch {
		case imp.Name == nil:
			alias = "pprof"
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name == "_":
			// Blank-imported for side effects only; runtime/pprof has
			// none worth mentioning, but there is nothing to flag.
			imported = false
		default:
			alias = imp.Name.Name
		}
	}
	return alias, dot, imported
}

func scanFile(fset *token.FileSet, path string, file *ast.File, guard *Guard) []Finding {
	alias, dot, imported := pprofAlias(file)
	if !imported {
		return nil
	}

	var findings []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !isPprofLabelsCall(call, alias, dot) {
			return true
		}
		findings = append(findings, checkLabelsArgs(fset, path, call, guard)...)
		return true
	})
	return findings
}

// isPprofLabelsCall reports whether call is a call to runtime/pprof's
// Labels function, given how this file refers to the package (see
// pprofAlias).
func isPprofLabelsCall(call *ast.CallExpr, alias string, dot bool) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if fn.Sel.Name != "Labels" {
			return false
		}
		ident, ok := fn.X.(*ast.Ident)
		return ok && alias != "" && ident.Name == alias
	case *ast.Ident:
		return dot && fn.Name == "Labels"
	}
	return false
}

// checkLabelsArgs inspects one pprof.Labels(...) call's argument list.
// Only positions the parser can fully evaluate (string literals in every
// key/value slot) are checked; anything else — a variable, a spread
// call, string concatenation — is silently skipped rather than guessed
// at.
func checkLabelsArgs(fset *token.FileSet, path string, call *ast.CallExpr, guard *Guard) []Finding {
	args := call.Args
	if len(args) == 1 {
		if _, ok := args[0].(*ast.Ellipsis); ok {
			return nil // Labels(argsSlice...): nothing literal to check.
		}
	}
	if len(args)%2 != 0 {
		pos := fset.Position(call.Pos())
		return []Finding{{
			Code:     CodeMalformedLabelsCall,
			Severity: SeverityCritical,
			File:     path,
			Line:     pos.Line,
			Col:      pos.Column,
			Message:  fmt.Sprintf("pprof.Labels called with %d literal arguments (odd count): this panics at runtime", len(args)),
		}}
	}

	var findings []Finding
	for i := 0; i+1 < len(args); i += 2 {
		keyLit, keyOK := stringLiteral(args[i])
		valLit, valOK := stringLiteral(args[i+1])
		if !keyOK {
			continue
		}
		pos := fset.Position(args[i].Pos())
		if guard.Sensitive(keyLit) {
			findings = append(findings, Finding{
				Code:     CodeSensitiveLabelKey,
				Severity: SeverityWarning,
				File:     path,
				Line:     pos.Line,
				Col:      pos.Column,
				Key:      keyLit,
				Message:  fmt.Sprintf("pprof.Labels key %q matches a sensitive pattern; its value will be printed in goroutine tracebacks once tracebacklabels is on", keyLit),
			})
			continue
		}
		if valOK {
			if name, ok := guard.SensitiveValue(valLit); ok {
				findings = append(findings, Finding{
					Code:     CodeSensitiveLabelValue,
					Severity: SeverityWarning,
					File:     path,
					Line:     pos.Line,
					Col:      pos.Column,
					Key:      keyLit,
					Message:  fmt.Sprintf("pprof.Labels value under key %q looks like a %s even though the key itself isn't flagged", keyLit, name),
				})
			}
		}
	}
	return findings
}

// stringLiteral reports the unquoted string value of e when e is a
// string literal, and false otherwise.
func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}
