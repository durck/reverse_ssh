package mux

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NHAS/reverse_ssh/pkg/mux/protocols"
)

func TestClassifyHTTPRequestDefaultPaths(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		expect protocols.Type
	}{
		{name: "wss", line: "GET /ws HTTP/1.1\r\n", expect: protocols.Websockets},
		{name: "polling head", line: "HEAD /push?key=abc HTTP/1.1\r\n", expect: protocols.HTTP},
		{name: "polling get", line: "GET /push/123?id=abc HTTP/1.1\r\n", expect: protocols.HTTP},
		{name: "polling post", line: "POST /push?id=abc HTTP/1.1\r\n", expect: protocols.HTTP},
		{name: "wrong websocket path", line: "GET /not-ws HTTP/1.1\r\n", expect: protocols.HTTPDownload},
		{name: "wrong push path", line: "HEAD /not-push?key=abc HTTP/1.1\r\n", expect: protocols.HTTPDownload},
		{name: "wrong polling get shape", line: "GET /push?id=abc HTTP/1.1\r\n", expect: protocols.HTTPDownload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyHTTPRequest([]byte(tt.line), "/ws", "/push"); got != tt.expect {
				t.Fatalf("classifyHTTPRequest(%q) = %q, want %q", tt.line, got, tt.expect)
			}
		})
	}
}

func TestClassifyHTTPRequestCustomPaths(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		expect protocols.Type
	}{
		{name: "custom websocket", line: "GET /socket HTTP/1.1\r\n", expect: protocols.Websockets},
		{name: "custom polling", line: "HEAD /push-custom?key=abc HTTP/1.1\r\n", expect: protocols.HTTP},
		{name: "default websocket rejected", line: "GET /ws HTTP/1.1\r\n", expect: protocols.HTTPDownload},
		{name: "default polling rejected", line: "HEAD /push?key=abc HTTP/1.1\r\n", expect: protocols.HTTPDownload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyHTTPRequest([]byte(tt.line), "/socket", "/push-custom"); got != tt.expect {
				t.Fatalf("classifyHTTPRequest(%q) = %q, want %q", tt.line, got, tt.expect)
			}
		})
	}
}

func TestMetadataFromRequestTrustsConfiguredProxy(t *testing.T) {
	_, trusted, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	m := &Multiplexer{config: MultiplexerConfig{TrustedProxyCIDRs: []*net.IPNet{trusted}}}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.10")
	req.Header.Set("X-Real-IP", "198.51.100.10")

	metadata := m.metadataFromRequest(req, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4444}, "wss")
	if metadata.Transport != "wss" {
		t.Fatalf("transport = %q", metadata.Transport)
	}
	if metadata.RealClientIP != "198.51.100.10" {
		t.Fatalf("real client ip = %q", metadata.RealClientIP)
	}
	if metadata.ProxySourceIP != "192.0.2.10" {
		t.Fatalf("proxy source ip = %q", metadata.ProxySourceIP)
	}
}

func TestBufferedConnReadUsesPrefixWithoutBlocking(t *testing.T) {
	request := []byte("GET /main.sh HTTP/1.0\r\nHost: example\r\n\r\n")
	blocking := &blockingConn{}
	bc := &bufferedConn{prefix: append([]byte(nil), request...), conn: blocking}

	buf := make([]byte, 4096)
	type readResult struct {
		n   int
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		n, err := bc.Read(buf)
		done <- readResult{n: n, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("read failed: %v", result.err)
		}
		if result.n != len(request) {
			t.Fatalf("read %d bytes, want %d", result.n, len(request))
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("bufferedConn.Read blocked waiting for underlying conn")
	}
	if blocking.readCalled {
		t.Fatal("bufferedConn should not read from underlying conn while prefix has data")
	}
}

type blockingConn struct {
	readCalled bool
}

func (c *blockingConn) Read([]byte) (int, error) {
	c.readCalled = true
	select {}
}

func (c *blockingConn) Write([]byte) (int, error)  { return 0, nil }
func (c *blockingConn) Close() error               { return nil }
func (c *blockingConn) LocalAddr() net.Addr        { return nil }
func (c *blockingConn) RemoteAddr() net.Addr       { return nil }
func (c *blockingConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingConn) SetWriteDeadline(time.Time) error { return nil }

func TestBufferedConnCarriesMetadata(t *testing.T) {
	conn := withMetadata(&testConn{remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4444}}, ConnectionMetadata{
		Transport:     "wss",
		RealClientIP:  "198.51.100.10",
		ProxySourceIP: "192.0.2.10",
	})
	buffered := &bufferedConn{conn: conn}

	metadata := Metadata(buffered)
	if metadata.Transport != "wss" || metadata.ProxySourceIP != "192.0.2.10" {
		t.Fatalf("metadata lost: %+v", metadata)
	}
	if got := buffered.RemoteAddr().String(); got != "198.51.100.10:0" {
		t.Fatalf("remote addr = %q", got)
	}
}

type testConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *testConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func TestMetadataFromRequestIgnoresUntrustedProxy(t *testing.T) {
	_, trusted, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	m := &Multiplexer{config: MultiplexerConfig{TrustedProxyCIDRs: []*net.IPNet{trusted}}}
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("X-Real-IP", "198.51.100.10")

	metadata := m.metadataFromRequest(req, &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 4444}, "wss")
	if metadata.RealClientIP != "" {
		t.Fatalf("untrusted real client ip = %q", metadata.RealClientIP)
	}
	if metadata.ProxySourceIP != "" {
		t.Fatalf("untrusted proxy source ip = %q", metadata.ProxySourceIP)
	}
}
