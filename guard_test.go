package tracelabelguard

import (
	"context"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"testing"
)

func TestGuardRedact(t *testing.T) {
	g := NewGuard()

	tests := []struct {
		name string
		kvs  []string
		want []string
	}{
		{
			name: "sensitive key redacted",
			kvs:  []string{"session_token", "sk_live_abc123"},
			want: []string{"session_token", "[REDACTED]"},
		},
		{
			name: "case and separators normalized",
			kvs:  []string{"User-Email", "victim@example.com"},
			want: []string{"User-Email", "[REDACTED]"},
		},
		{
			name: "ordinary key kept",
			kvs:  []string{"request_id", "req-123"},
			want: []string{"request_id", "req-123"},
		},
		{
			name: "value-shape JWT redacted despite innocuous key",
			kvs:  []string{"extra", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ-abcdefghijklmno"},
			want: []string{"extra", "[REDACTED]"},
		},
		{
			name: "known secret prefix redacted despite innocuous key",
			kvs:  []string{"extra", "sk_live_SUPER_SECRET_TOKEN_12345"},
			want: []string{"extra", "[REDACTED]"},
		},
		{
			name: "multiple pairs, only sensitive ones redacted",
			kvs:  []string{"tenant_id", "t-9", "password", "hunter2", "region", "eu-west-1"},
			want: []string{"tenant_id", "t-9", "password", "[REDACTED]", "region", "eu-west-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.Redact(tt.kvs...)
			if len(got) != len(tt.want) {
				t.Fatalf("Redact(%v) = %v, want %v", tt.kvs, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Redact(%v)[%d] = %q, want %q", tt.kvs, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGuardRedactDoesNotMutateInput(t *testing.T) {
	g := NewGuard()
	kvs := []string{"password", "hunter2"}
	orig := append([]string(nil), kvs...)
	_ = g.Redact(kvs...)
	for i := range kvs {
		if kvs[i] != orig[i] {
			t.Fatalf("Redact mutated its input: got %v, want %v", kvs, orig)
		}
	}
}

func TestGuardRedactOddArgsPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected Redact to panic on an odd number of arguments, like pprof.Labels does")
		}
	}()
	NewGuard().Redact("only-a-key")
}

func TestGuardCustomPatterns(t *testing.T) {
	g := &Guard{KeyPatterns: []string{"tenant"}}
	got := g.Redact("tenant_id", "acme-corp", "session_token", "sk_live_abc123")
	if got[1] != "[REDACTED]" {
		t.Errorf("tenant_id should be redacted under custom patterns, got %q", got[1])
	}
	if got[3] != "sk_live_abc123" {
		t.Errorf("session_token should NOT be redacted when KeyPatterns doesn't include it and value detectors are empty, got %q", got[3])
	}
}

func TestGuardCustomRedactedText(t *testing.T) {
	g := NewGuard()
	g.Redacted = "***"
	got := g.Redact("password", "hunter2")
	if got[1] != "***" {
		t.Errorf("got %q, want %q", got[1], "***")
	}
}

// TestGuardEndToEndTraceback is the real, non-synthetic regression test
// for the whole point of this package: a value redacted by Guard must
// not appear in an actual goroutine traceback captured via
// runtime/debug.Stack() while running inside a labeled pprof.Do scope.
// This does not assume tracebacklabels is on (it may not be, depending
// on the toolchain and go.mod running the test) — it only asserts that
// IF the label reaches the traceback, its value is the redacted one.
func TestGuardEndToEndTraceback(t *testing.T) {
	g := NewGuard()
	const secret = "sk_live_SUPER_SECRET_TOKEN_12345"

	var stack string
	g.Do(context.Background(), []string{"session_token", secret}, func(ctx context.Context) {
		stack = string(debug.Stack())
	})

	if strings.Contains(stack, secret) {
		t.Fatalf("guarded traceback leaked the secret value:\n%s", stack)
	}
	// Whether or not tracebacklabels happens to be on for this test
	// binary, the label must not carry the raw secret through pprof
	// either: check the label as pprof itself would see it.
	g.Do(context.Background(), []string{"session_token", secret}, func(ctx context.Context) {
		v, ok := pprof.Label(ctx, "session_token")
		if !ok {
			t.Fatal("expected session_token label to be set")
		}
		if v == secret {
			t.Fatalf("label value was not redacted before reaching pprof: %q", v)
		}
		if v != g.redactedText() {
			t.Fatalf("label value = %q, want %q", v, g.redactedText())
		}
	})
}

func TestPackageLevelHelpersUseDefaultGuard(t *testing.T) {
	ls := Labels("password", "hunter2")
	ctx := pprof.WithLabels(context.Background(), ls)
	v, ok := pprof.Label(ctx, "password")
	if !ok || v != DefaultRedactedText {
		t.Fatalf("Labels() did not redact via the default guard: v=%q ok=%v", v, ok)
	}

	ctx2 := WithLabels(context.Background(), "password", "hunter2")
	v2, ok2 := pprof.Label(ctx2, "password")
	if !ok2 || v2 != DefaultRedactedText {
		t.Fatalf("WithLabels() did not redact via the default guard: v=%q ok=%v", v2, ok2)
	}

	var got string
	Do(context.Background(), []string{"password", "hunter2"}, func(ctx context.Context) {
		got, _ = pprof.Label(ctx, "password")
	})
	if got != DefaultRedactedText {
		t.Fatalf("Do() did not redact via the default guard: got %q", got)
	}
}
