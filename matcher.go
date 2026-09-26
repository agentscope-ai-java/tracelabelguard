package tracelabelguard

import "strings"

// DefaultKeyPatterns is the conservative-but-useful set of substrings a
// label key is checked against, case-insensitively, after normalization
// (see normalizeKey). It is deliberately biased towards recall: it will
// over-redact before it under-redacts, which is documented in the
// package README under "What this does not do".
var DefaultKeyPatterns = []string{
	"token",
	"secret",
	"password",
	"passwd",
	"apikey",
	"api_key",
	"authorization",
	"cookie",
	"session",
	"email",
	"ssn",
	"credit",
	"card",
	"private_key",
	"privatekey",
}

// ValueDetector recognizes label values that look sensitive by shape,
// independent of the key they were attached under.
type ValueDetector struct {
	// Name identifies the detector in a Finding or a redaction reason.
	Name string
	// Match reports whether value looks like the thing Name describes.
	Match func(value string) bool
}

// DefaultValueDetectors is the built-in set of shape-based checks: things
// that look like a JWT or carry a well-known secret-key prefix. It is
// intentionally small — a short, low-false-positive list, not an attempt
// at exhaustive secret scanning.
var DefaultValueDetectors = []ValueDetector{
	{Name: "jwt", Match: looksLikeJWT},
	{Name: "known-secret-prefix", Match: hasKnownSecretPrefix},
}

// knownSecretPrefixes are literal prefixes used by widely deployed
// providers for live secret material. The list is short on purpose: each
// entry has to be distinctive enough that matching it is very unlikely
// to be a false positive.
var knownSecretPrefixes = []string{
	"sk_live_", "sk_test_", "pk_live_", "rk_live_", // Stripe
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", // GitHub
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", // Slack
	"AIza", // Google API key
	"AKIA", // AWS access key ID
	"ASIA", // AWS temporary access key ID
}

func hasKnownSecretPrefix(v string) bool {
	for _, p := range knownSecretPrefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// looksLikeJWT reports whether v has the three-dot-separated,
// base64url-alphabet shape of a JSON Web Token. It does not decode or
// verify anything — a JWT-shaped string that fails signature
// verification elsewhere still deserves redaction from a traceback.
func looksLikeJWT(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) < 8 {
			return false
		}
		for _, r := range p {
			if !isBase64URLRune(r) {
				return false
			}
		}
	}
	return true
}

func isBase64URLRune(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-' || r == '_' || r == '=':
		return true
	}
	return false
}

// normalizeKey lowercases a label key and strips underscores, hyphens
// and dots, so "Session-Token", "session_token" and "SESSIONTOKEN" all
// compare equal to the pattern "session" + "token" would suggest. This
// is what lets a short pattern list like DefaultKeyPatterns catch the
// naming conventions people actually use.
func normalizeKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch r {
		case '_', '-', '.', ' ':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.ToLower(b.String())
}

// KeySensitive reports whether key matches one of patterns after
// normalization (case-insensitive, separators stripped from both sides).
// An empty pattern is ignored.
func KeySensitive(key string, patterns []string) bool {
	nk := normalizeKey(key)
	for _, p := range patterns {
		np := normalizeKey(p)
		if np == "" {
			continue
		}
		if strings.Contains(nk, np) {
			return true
		}
	}
	return false
}
