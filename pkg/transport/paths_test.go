package transport

import "testing"

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		fallback string
		want     string
	}{
		{name: "fallback", fallback: "/ws", want: "/ws"},
		{name: "adds slash", input: "push", fallback: "/ws", want: "/push"},
		{name: "trims trailing slash", input: "/push/", fallback: "/ws", want: "/push"},
		{name: "keeps root", input: "/", fallback: "/ws", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizePath(tt.input, tt.fallback); got != tt.want {
				t.Fatalf("NormalizePath(%q, %q) = %q, want %q", tt.input, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestJoinPushPath(t *testing.T) {
	if got := JoinPushPath("/custom/", "123"); got != "/custom/123" {
		t.Fatalf("JoinPushPath = %q", got)
	}
}
