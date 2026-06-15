package client

import "testing"

func TestParseWinINETProxyString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"single host:port", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"single with whitespace", "  proxy.local:3128  ", "http://proxy.local:3128"},
		{"per-scheme http preferred", "http=10.0.0.1:8080;https=10.0.0.1:8443", "http://10.0.0.1:8080"},
		{"per-scheme https when no http", "https=10.0.0.1:8443;ftp=10.0.0.1:21", "http://10.0.0.1:8443"},
		{"per-scheme socks", "socks=10.0.0.1:1080", "socks5://10.0.0.1:1080"},
		{"per-scheme socks fallback", "ftp=10.0.0.1:21;socks=10.0.0.1:1080", "socks5://10.0.0.1:1080"},
		{"per-scheme order preserved http over socks", "socks=10.0.0.1:1080;http=10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"per-scheme only ftp ignored", "ftp=10.0.0.1:21", ""},
		{"per-scheme malformed segment", "http=;https=10.0.0.1:8443", "http://10.0.0.1:8443"},
		{"per-scheme uppercase keys", "HTTP=10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"per-scheme stray semicolons", ";;http=10.0.0.1:8080;;", "http://10.0.0.1:8080"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseWinINETProxyString(tc.in)
			if got != tc.want {
				t.Errorf("parseWinINETProxyString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
