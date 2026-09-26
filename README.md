# tracelabelguard

Keeps sensitive `runtime/pprof` label values out of goroutine tracebacks — and a
static scanner that flags the label call sites likely to leak them.

```
=== leaked: raw pprof.Labels / pprof.Do ===
goroutine 1 [running] {request_id: "req-8f3c2a", session_token: sk_live_SUPER_SECRET_TOKEN_12345, user_email: "victim@example.com"}:

=== redacted: same values through tracelabelguard.Do ===
goroutine 1 [running] {request_id: "req-8f3c2a", session_token: "[REDACTED]", user_email: "[REDACTED]"}:
```

That's real output from `go run ./examples/leakdemo` on Go 1.27.1. Same key/value
payload, same call shape, the only difference is which function attached the labels.

## The problem

Go 1.27 flipped the `tracebacklabels` GODEBUG default from off to on
(`$GOROOT/src/internal/godebugs/table.go`):

```go
{Name: "tracebacklabels", Package: "runtime", Changed: 27, Old: "0", Opaque: true},
```

Before that change, a label attached with `runtime/pprof.Do` or `pprof.WithLabels`
was invisible outside the profiler. After it, every goroutine header — in a panic,
in `runtime/debug.Stack()`, in a crash dump forwarded to Sentry or a log
aggregator — prints the label's key and value inline:

```
default:                     goroutine 1 [running] {session_token: sk_live_SUPER_SECRET_TOKEN_12345, user_email: "victim@example.com"}:
GODEBUG=tracebacklabels=0:   goroutine 1 [running]:
```

(Both lines above are real output, captured directly on this machine with
`go1.27.1`, running the exact same program with and without the `GODEBUG` override.)

pprof labels are a widely recommended place to attach a request ID, a user ID, or a
tenant ID for profiling — and in practice, people also put session tokens,
passwords and emails there, because nothing in the API discourages it. Any of that
now prints by default wherever a stack trace is printed. The only advice
circulating for this is "turn `tracebacklabels` off everywhere," which depends on
every deployment remembering to set a `GODEBUG` value and breaks the moment
someone forgets.

## What this does instead

1. **A runtime guard** (`Guard`, and package-level `Labels`/`Do`/`WithLabels`)
   wraps `runtime/pprof.Labels` / `pprof.Do` / `pprof.WithLabels` and redacts a
   label's value — before it is ever attached — when its **key** matches a
   sensitive pattern (`token`, `secret`, `password`, `email`, `session`, ...), or
   when its **value** looks like a JWT or carries a known live-secret prefix
   (`sk_live_`, `ghp_`, `AKIA`, ...), even under an innocuous key.
2. **A stdlib-only static scanner** (`Scan`, built on `go/ast` + `go/parser`, not
   `golang.org/x/tools`) that walks a module's source, flags `pprof.Labels(...)`
   call sites with suspicious literal keys or values, and reports whether the
   module's `go.mod` `go` directive puts it on a toolchain where
   `tracebacklabels` defaults on.
3. **A CLI** (`cmd/tracelabelguard`) wrapping the scanner.

## Install

```sh
go get github.com/__GH_OWNER__/tracelabelguard
```

Go 1.21+ (this module's own `go.mod` targets 1.27.1, since that's the version the
gap it documents applies to; the library itself has no version-specific code).
Standard library only — no runtime dependencies.

## Use: the runtime guard

```go
import (
	"context"
	"github.com/__GH_OWNER__/tracelabelguard"
)

func handle(ctx context.Context, sessionToken, userEmail, requestID string) {
	tracelabelguard.Do(ctx, []string{
		"session_token", sessionToken,
		"user_email", userEmail,
		"request_id", requestID,
	}, func(ctx context.Context) {
		// ... your handler, profiled with these labels ...
	})
}
```

`session_token` and `user_email` are redacted to `[REDACTED]` before they ever
reach `runtime/pprof`; `request_id` passes through untouched. A goroutine dump
taken from inside that scope shows:

```
goroutine 1 [running] {request_id: "req-8f3c2a", session_token: "[REDACTED]", user_email: "[REDACTED]"}:
```

Drop-in replacements exist for all three `runtime/pprof` entry points that carry
labels:

| `runtime/pprof` | `tracelabelguard` |
| --- | --- |
| `pprof.Labels(kvs...)` | `tracelabelguard.Labels(kvs...)` |
| `pprof.WithLabels(ctx, labels)` | `tracelabelguard.WithLabels(ctx, kvs...)` |
| `pprof.Do(ctx, labels, fn)` | `tracelabelguard.Do(ctx, kvs, fn)` |

Each package-level function uses a shared default `Guard`. Construct your own for
custom patterns:

```go
g := tracelabelguard.NewGuard()
g.KeyPatterns = append(g.KeyPatterns, "tenant_secret") // extend, don't replace
g.Redacted = "***"                                     // customize the placeholder

g.Do(ctx, []string{"tenant_secret", tenantSecret}, func(ctx context.Context) { ... })
```

### `Guard` fields

| Field | Default | What it does |
| --- | --- | --- |
| `KeyPatterns` | `DefaultKeyPatterns` (`token`, `secret`, `password`, `passwd`, `apikey`, `api_key`, `authorization`, `cookie`, `session`, `email`, `ssn`, `credit`, `card`, `private_key`, ...) | Matched case-insensitively against each label key with separators (`_`, `-`, `.`, spaces) stripped, so `Session-Token`, `session_token` and `SESSIONTOKEN` all match. |
| `ValueDetectors` | `DefaultValueDetectors` (JWT shape, known live-secret prefixes) | Matched against each label **value**, independent of its key, so a token stuffed under an innocuous key (`extra`, `ctx`, ...) is still caught. |
| `Redacted` | `"[REDACTED]"` | The string substituted for a sensitive value. |

`Guard.Redact(kvs...)` returns a redacted copy without touching `pprof` at all, if
you want the value for something other than a label. `Guard.Labels`/`WithLabels`/`Do`
panic on an odd number of arguments — matching `pprof.Labels`'s own behavior, since
whatever reached `pprof.Labels` unredacted would panic there anyway.

## Use: the scanner and CLI

```sh
go install github.com/__GH_OWNER__/tracelabelguard/cmd/tracelabelguard@latest
tracelabelguard --dir ./myservice
```

Real output, run against a small demo module whose `go.mod` says `go 1.27.1` and
whose source calls `pprof.Labels("session_token", ..., "user_email", ..., "request_id", ...)`:

```
scanned 1 file(s) under cli-demo
go.mod: cli-demo/go.mod (go 1.27.1)

3 finding(s): 0 critical, 2 warning, 1 info

WARNING  sensitive-label-key      cli-demo/handler.go:10:3
         pprof.Labels key "session_token" matches a sensitive pattern; its value will be printed in goroutine tracebacks once tracebacklabels is on
WARNING  sensitive-label-key      cli-demo/handler.go:11:3
         pprof.Labels key "user_email" matches a sensitive pattern; its value will be printed in goroutine tracebacks once tracebacklabels is on
INFO     tracebacklabels-default-on cli-demo/go.mod
         go.mod declares "go 1.27.1": tracebacklabels defaults ON, pprof label values print in goroutine tracebacks unless GODEBUG=tracebacklabels=0
```

Exit code was `1` (warnings present). `request_id` produced no finding.

### Flags

| Flag | Default | What it does |
| --- | --- | --- |
| `--dir` | `.` | Directory to scan. |
| `--json` | `false` | Print the full `ScanResult` as JSON instead of the summary. |
| `--fail-on` | `critical,warning` | Comma-separated finding codes or severities that make the exit code `1`. |
| `--include-tests` | `false` | Also scan `_test.go` files. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran cleanly; no finding matched `--fail-on`. |
| `1` | A finding matched `--fail-on`. |
| `2` | tracelabelguard itself failed to analyse the input (bad flags, unreadable directory, a `.go` file that failed to parse). A missing `go.mod` is **not** a failure here — it produces an informational `go-version-unknown` finding, since the scanner can still check the source. |

### Programmatic use

```go
res, err := tracelabelguard.Scan(tracelabelguard.ScanOptions{Dir: "./myservice"})
if err != nil {
    // could not analyse: bad directory, parse error, ...
}
if res.FailOn([]string{"critical", "warning"}) {
    // findings present
}
```

## What this does NOT do

- **It cannot redact labels attached by third-party code.** If a dependency calls
  `runtime/pprof.Labels` directly — its own instrumentation, a framework's request
  middleware — this package never sees that call and cannot redact it. The guard
  only protects labels attached through `tracelabelguard.Do` / `.Labels` /
  `.WithLabels` (or a `Guard` you construct) in your own code.
- **The scanner only sees string literals.** A key or value built from a variable,
  a constant defined elsewhere, string concatenation, or a function call is
  silently skipped — the parser has no value to check. `pprof.Labels(key, token)`
  where `key` is a variable holding `"session_token"` will not be flagged even
  though the runtime guard would still redact it correctly if you used
  `tracelabelguard.Labels` instead.
- **The key-pattern list is a heuristic, not a guarantee.** It is biased toward
  catching real leaks (recall) over avoiding false positives (precision):
  - It **will over-redact**: a key like `session_id` contains `session` and gets
    redacted even though a session ID is not usually secret on its own; `cardinal_direction`
    would trip `card`.
  - It **will miss things**: a key like `x_forwarded_secret_header` normalizes
    fine and matches `secret`, but a bespoke internal name like `svc_shared_bearer`
    matches nothing in the default list unless you add `bearer`.
  - The value detectors (JWT shape, `sk_live_`-style prefixes) are a short,
    deliberately narrow list of well-known formats, not a general secret scanner.
- **`Guard` cannot un-print a value that already reached `pprof` unredacted.** It
  only works if you route the label-attaching call through it in the first place.
- **The scanner does not evaluate `pprof.Labels(argsSlice...)` calls** (a single
  spread argument): there is nothing literal in the call for `go/ast` to check, so
  these are silently skipped rather than guessed at.

## Design notes

- Key matching normalizes both the key and each pattern (lowercase, strip `_ - . `)
  before comparing as substrings. This is what lets a dozen-entry pattern list
  catch `Session-Token`, `session_token`, `SESSIONTOKEN` and `sessionToken`
  without needing one entry per naming convention.
- The scanner tracks each file's own import of `runtime/pprof` — including a
  renamed import (`pp "runtime/pprof"`) and a dot import (`. "runtime/pprof"`) —
  rather than assuming the package is always called `pprof`, so it isn't fooled by
  either an alias or defeated by one.
- `go.mod`'s `go` directive, not the toolchain that happens to run `go build`,
  determines whether `tracebacklabels` defaults on: GODEBUG defaults are pinned to
  a module's declared language version for backward compatibility. The scanner
  reads `go.mod`'s `go` line directly (a small hand-written reader, matching the
  approach `modtrust` in this same `utils/` directory uses for its own
  `go.mod`/`go.sum` reading, rather than pulling in `golang.org/x/mod/modfile`, a
  separate module) and compares it with the standard library's own `go/version`
  package.
- `Guard.Labels`/`.WithLabels`/`.Do` intentionally panic on an odd argument count,
  same as `pprof.Labels` itself. That is a caller bug, not a redaction decision:
  if `Redact` swallowed it silently, the same malformed call would just panic one
  frame further down inside `pprof.Labels` anyway, with less useful context.

## Develop

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
gofmt -l .
```

All four were run against this exact tree; `gofmt -l .` printed nothing.

## License

MIT
