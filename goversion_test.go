package tracelabelguard

import "testing"

func TestParseGoDirective(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "simple",
			data: "module example.com/m\n\ngo 1.27.1\n",
			want: "1.27.1",
		},
		{
			name: "no patch version",
			data: "module example.com/m\n\ngo 1.21\n",
			want: "1.21",
		},
		{
			name: "with trailing comment",
			data: "module example.com/m\n\ngo 1.27 // pinned deliberately\n",
			want: "1.27",
		},
		{
			name: "no go directive",
			data: "module example.com/m\n",
			want: "",
		},
		{
			name: "empty file",
			data: "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseGoDirective([]byte(tt.data)); got != tt.want {
				t.Errorf("parseGoDirective(%q) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestTracebacklabelsDefault(t *testing.T) {
	tests := []struct {
		directive string
		wantOn    bool
		wantOK    bool
	}{
		{"1.27.1", true, true},
		{"1.27", true, true},
		{"1.28", true, true},
		{"1.26.9", false, true},
		{"1.20", false, true},
		{"not-a-version", false, false},
		{"", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.directive, func(t *testing.T) {
			on, ok := tracebacklabelsDefault(tt.directive)
			if on != tt.wantOn || ok != tt.wantOK {
				t.Errorf("tracebacklabelsDefault(%q) = (%v, %v), want (%v, %v)", tt.directive, on, ok, tt.wantOn, tt.wantOK)
			}
		})
	}
}
