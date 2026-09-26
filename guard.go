package tracelabelguard

import (
	"context"
	"runtime/pprof"
)

// DefaultRedactedText replaces the value of any label a Guard decides is
// sensitive.
const DefaultRedactedText = "[REDACTED]"

// Guard redacts sensitive values out of runtime/pprof labels before they
// are ever attached to a goroutine, so a traceback shows a placeholder
// instead of the original value. The zero value is not ready to use;
// construct one with NewGuard.
type Guard struct {
	// KeyPatterns is checked against each label key, case-insensitively
	// and with separators stripped (see KeySensitive). A key that
	// matches has its value redacted regardless of the value's shape.
	KeyPatterns []string
	// ValueDetectors is checked against each label value regardless of
	// its key, so a token-shaped value attached under an innocuous key
	// (say, "ctx" or "extra") still gets redacted.
	ValueDetectors []ValueDetector
	// Redacted is substituted for a sensitive value. Defaults to
	// DefaultRedactedText when empty.
	Redacted string
}

// NewGuard returns a Guard configured with DefaultKeyPatterns and
// DefaultValueDetectors. The returned Guard owns its own copies of those
// slices, so callers can freely append to or trim them.
func NewGuard() *Guard {
	g := &Guard{
		KeyPatterns:    append([]string(nil), DefaultKeyPatterns...),
		ValueDetectors: append([]ValueDetector(nil), DefaultValueDetectors...),
		Redacted:       DefaultRedactedText,
	}
	return g
}

func (g *Guard) redactedText() string {
	if g.Redacted != "" {
		return g.Redacted
	}
	return DefaultRedactedText
}

// Sensitive reports whether key, by itself, marks its value for
// redaction under g's KeyPatterns.
func (g *Guard) Sensitive(key string) bool {
	return KeySensitive(key, g.KeyPatterns)
}

// SensitiveValue reports whether value matches one of g's
// ValueDetectors, independent of its key, and if so returns the
// detector's name.
func (g *Guard) SensitiveValue(value string) (name string, ok bool) {
	for _, d := range g.ValueDetectors {
		if d.Match != nil && d.Match(value) {
			return d.Name, true
		}
	}
	return "", false
}

// Redact returns a copy of kvs (an alternating key/value sequence, the
// same shape pprof.Labels takes) with every value replaced by g's
// Redacted text when its key matches KeyPatterns or its value matches a
// ValueDetector. Like pprof.Labels, Redact panics if len(kvs) is odd —
// that is a caller bug, not a redaction decision, and pprof.Labels would
// panic on it anyway once Redact's output reached it.
func (g *Guard) Redact(kvs ...string) []string {
	if len(kvs)%2 != 0 {
		panic("tracelabelguard: uneven number of arguments to Redact")
	}
	out := make([]string, len(kvs))
	copy(out, kvs)
	for i := 0; i+1 < len(out); i += 2 {
		key, val := out[i], out[i+1]
		if g.Sensitive(key) {
			out[i+1] = g.redactedText()
			continue
		}
		if _, ok := g.SensitiveValue(val); ok {
			out[i+1] = g.redactedText()
		}
	}
	return out
}

// Labels is a drop-in replacement for runtime/pprof.Labels: it takes the
// same alternating key/value strings and returns a pprof.LabelSet, but
// with sensitive values redacted first via Redact.
func (g *Guard) Labels(kvs ...string) pprof.LabelSet {
	return pprof.Labels(g.Redact(kvs...)...)
}

// WithLabels is a drop-in replacement for runtime/pprof.WithLabels: it
// takes ctx and the same alternating key/value strings pprof.Labels
// would, redacts sensitive values, and returns the resulting context.
func (g *Guard) WithLabels(ctx context.Context, kvs ...string) context.Context {
	return pprof.WithLabels(ctx, g.Labels(kvs...))
}

// Do is a drop-in replacement for runtime/pprof.Do: it takes ctx, the
// same alternating key/value strings pprof.Labels would (redacted before
// attachment), and runs fn with the resulting context, exactly like
// pprof.Do(ctx, pprof.Labels(kvs...), fn).
func (g *Guard) Do(ctx context.Context, kvs []string, fn func(context.Context)) {
	pprof.Do(ctx, g.Labels(kvs...), fn)
}

// defaultGuard backs the package-level Labels/WithLabels/Do functions.
var defaultGuard = NewGuard()

// Labels calls defaultGuard.Labels using the package's default key
// patterns and value detectors. Use a Guard directly to customize them.
func Labels(kvs ...string) pprof.LabelSet {
	return defaultGuard.Labels(kvs...)
}

// WithLabels calls defaultGuard.WithLabels.
func WithLabels(ctx context.Context, kvs ...string) context.Context {
	return defaultGuard.WithLabels(ctx, kvs...)
}

// Do calls defaultGuard.Do.
func Do(ctx context.Context, kvs []string, fn func(context.Context)) {
	defaultGuard.Do(ctx, kvs, fn)
}
