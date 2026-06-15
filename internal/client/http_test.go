package client

import "testing"

func TestHTTPConnURLsUseDefaultPushPath(t *testing.T) {
	conn := &HTTPConn{address: "https://example.com", pushPath: "/push", ID: "id1", start: 7}

	if got := conn.initURL("abc"); got != "https://example.com/push?key=abc" {
		t.Fatalf("initURL = %q", got)
	}
	if got := conn.readURL(); got != "https://example.com/push/7?id=id1" {
		t.Fatalf("readURL = %q", got)
	}
	if got := conn.writeURL(); got != "https://example.com/push?id=id1" {
		t.Fatalf("writeURL = %q", got)
	}
}

func TestHTTPConnURLsUseCustomPushPath(t *testing.T) {
	conn := &HTTPConn{address: "https://example.com", pushPath: "/api/push", ID: "id1", start: 7}

	if got := conn.initURL("abc"); got != "https://example.com/api/push?key=abc" {
		t.Fatalf("initURL = %q", got)
	}
	if got := conn.readURL(); got != "https://example.com/api/push/7?id=id1" {
		t.Fatalf("readURL = %q", got)
	}
	if got := conn.writeURL(); got != "https://example.com/api/push?id=id1" {
		t.Fatalf("writeURL = %q", got)
	}
}
