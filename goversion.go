package tracelabelguard

import (
	"bufio"
	"go/version"
	"strings"
)

// tracebacklabelsChangedAt is the Go language version at which the
// runtime's tracebacklabels GODEBUG setting flipped its default from off
// to on, per $GOROOT/src/internal/godebugs/table.go:
//
//	{Name: "tracebacklabels", Package: "runtime", Changed: 27, Old: "0", Opaque: true}
//
// GODEBUG defaults are pinned to a module's go.mod "go" directive, not to
// the toolchain used to build it: a module whose go directive is below
// this version keeps the old (off) default even when compiled with a
// 1.27+ toolchain, unless GODEBUG=tracebacklabels=1 or a //go:debug
// directive overrides it.
const tracebacklabelsChangedAt = "go1.27"

// parseGoDirective extracts the "go" directive's value from go.mod
// content, e.g. "1.27.1" from a line "go 1.27.1". It returns "" if no
// such directive is found. It intentionally does not parse the rest of
// go.mod (module, require, replace, ...); tracelabelguard only needs the
// language version.
func parseGoDirective(data []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "go" {
			return fields[1]
		}
	}
	return ""
}

// tracebacklabelsDefault reports, for a module whose go.mod "go"
// directive is goDirective (e.g. "1.27.1", without the "go" prefix),
// whether the tracebacklabels GODEBUG setting defaults on. ok is false
// when goDirective isn't a version go/version recognizes.
func tracebacklabelsDefault(goDirective string) (defaultOn, ok bool) {
	if goDirective == "" {
		return false, false
	}
	v := "go" + goDirective
	if !version.IsValid(v) {
		return false, false
	}
	// Compare at language-version granularity ("go1.27") so a directive
	// like "1.27.1" or "1.27rc1" still compares correctly against the
	// "go1.27" threshold.
	lang := version.Lang(v)
	return version.Compare(lang, tracebacklabelsChangedAt) >= 0, true
}
