package tracelabelguard

import "testing"

func TestKeySensitive(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"session_token", true},
		{"SessionToken", true},
		{"Session-Token", true},
		{"X-Api-Key", true},
		{"api_key", true},
		{"apikey", true},
		{"Authorization", true},
		{"authorization_header", true},
		{"Cookie", true},
		{"user_email", true},
		{"userEmail", true},
		{"ssn", true},
		{"credit_card_number", true},
		{"private_key", true},
		{"privateKey", true},
		{"password", true},
		{"passwd", true},
		{"request_id", false},
		{"tenant_id", false},
		{"region", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := KeySensitive(tt.key, DefaultKeyPatterns)
			if got != tt.want {
				t.Errorf("KeySensitive(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestLooksLikeJWT(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"real-shaped jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ-abcdefghijklmno", true},
		{"two segments", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", false},
		{"plain sentence", "the quick brown fox", false},
		{"short segments", "a.b.c", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeJWT(tt.value); got != tt.want {
				t.Errorf("looksLikeJWT(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestHasKnownSecretPrefix(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"sk_live_abcdef1234567890", true},
		{"sk_test_abcdef1234567890", true},
		{"ghp_abcdefghijklmnopqrstuvwxyz0123456789", true},
		{"xoxb-1234-5678-abcdef", true},
		{"AKIAABCDEFGHIJKLMNOP", true},
		{"plain-string", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := hasKnownSecretPrefix(tt.value); got != tt.want {
				t.Errorf("hasKnownSecretPrefix(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"session_token", "sessiontoken"},
		{"Session-Token", "sessiontoken"},
		{"X.Api.Key", "xapikey"},
		{"  spaced out  ", "spacedout"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeKey(tt.in); got != tt.want {
			t.Errorf("normalizeKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
