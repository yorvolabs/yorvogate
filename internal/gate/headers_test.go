package gate

import (
	"bufio"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// upgradeRequest sends a raw request that asks for an HTTP upgrade, and gives the status the gate
// answers with.
func upgradeRequest(t *testing.T, url, request string) int {
	t.Helper()

	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte(request))

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}

	return res.StatusCode
}

// A client's Connection header names the headers dropped on the way to Docker. Docker gets the
// gate's own instead, so what the gate sets (Content-Type) and forwards stays as it is.
func TestAClientsConnectionHeaderNamesNothing(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	hostile := "keep-alive, Upgrade, Content-Type, User-Agent, Accept, Traceparent, Content-Length"

	scope := "X-YorvoGate-Scope: jane\r\nX-YorvoGate-Token: " + token + "\r\n"
	listed := "User-Agent: Docker-Client/29.9.2\r\nAccept: application/json\r\nTraceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n"

	for name, c := range map[string]struct {
		request string
		body    bool
	}{
		"exec.start": {
			"POST /v1.56/exec/exec-jane/start HTTP/1.1\r\nHost: docker\r\n" + scope + listed + "Content-Type: application/json\r\nConnection: " + hostile + "\r\nUpgrade: tcp\r\nContent-Length: 16\r\n\r\n{\"Detach\":false}",
			true,
		},
		"container.attach": {
			"POST /v1.56/containers/jane-php-1/attach?stream=1 HTTP/1.1\r\nHost: docker\r\n" + scope + listed + "Connection: " + hostile + "\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
			false,
		},
		"container.attach-websocket": {
			"GET /v1.56/containers/jane-php-1/attach/ws?stream=1 HTTP/1.1\r\nHost: docker\r\n" + scope + listed + "Connection: " + hostile + "\r\nUpgrade: websocket\r\n\r\n",
			false,
		},
	} {
		before := d.count()
		if status := upgradeRequest(t, server.URL, c.request); status >= 400 {
			t.Errorf("%s: %d", name, status)

			continue
		}

		if d.count() != before+1 {
			t.Errorf("%s: didn't reach Docker", name)

			continue
		}

		got := d.last().header
		if v := got.Values("Connection"); len(v) != 1 || v[0] != "Upgrade" {
			t.Errorf("%s: Docker got Connection %q", name, v)
		}

		if got.Get("Upgrade") == "" {
			t.Errorf("%s: Docker got no Upgrade", name)
		}

		for _, h := range []string{"User-Agent", "Accept", "Traceparent"} {
			if got.Get(h) == "" {
				t.Errorf("%s: %s didn't reach Docker", name, h)
			}
		}

		if c.body && (got.Get("Content-Type") != "application/json" || !strings.Contains(d.last().body, `"Detach":false`)) {
			t.Errorf("%s: Docker got Content-Type %q and %q", name, got.Get("Content-Type"), d.last().body)
		}
	}

	// A request that doesn't upgrade: Docker gets no Connection, nor Upgrade, and the gate's
	// Content-Type
	header := map[string]string{"Connection": "Content-Type, Accept", "Accept": "application/json"}
	for k, v := range asJane {
		header[k] = v
	}

	if status, answer := send(t, server, "POST", "/v1.56/exec/exec-jane/start", `{"Detach":true}`, header); status != http.StatusOK {
		t.Fatalf("detached: %d %s", status, answer)
	}

	got := d.last().header
	if got.Get("Connection") != "" || got.Get("Upgrade") != "" || got.Get("Content-Type") != "application/json" || got.Get("Accept") != "application/json" {
		t.Errorf("detached: Docker got %v", got)
	}
}

// A WebSocket's handshake reaches Docker on the endpoint that takes one, and only there: without
// its key and version, Docker answers 400 and the attach never starts.
func TestAWebSocketsHandshakeIsForwarded(t *testing.T) {
	given := http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}, "Sec-Websocket-Version": {"13"}, "Sec-Websocket-Protocol": {"chat"}}

	out, _, err := forwarded(given, "container.attach-websocket", true)
	if err != nil || out.Get("Sec-Websocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" || out.Get("Sec-Websocket-Version") != "13" || out.Get("Sec-Websocket-Protocol") != "chat" {
		t.Errorf("attach-websocket: %v %v", out, err)
	}

	out, dropped, err := forwarded(given, "container.attach", true)
	if err != nil || out.Get("Sec-Websocket-Key") != "" || !slices.Contains(dropped, "Sec-Websocket-Key") {
		t.Errorf("attach (not a WebSocket): %v %v %v", out, dropped, err)
	}

	given["Sec-Websocket-Key"] = []string{strings.Repeat("k", 65)}
	if _, _, err := forwarded(given, "container.attach-websocket", true); err == nil {
		t.Error("a key longer than 64 bytes")
	}
}

func TestUpgradeIsForwardedOnlyWhenTheRequestUpgrades(t *testing.T) {
	given := http.Header{"Upgrade": {"tcp"}, "Connection": {"Upgrade, Accept"}, "Accept": {"application/json"}}

	out, _, err := forwarded(given, "exec.start", true)
	if err != nil || out.Get("Connection") != "Upgrade" || out.Get("Upgrade") != "tcp" || out.Get("Accept") != "application/json" {
		t.Errorf("upgrading: %v %v", out, err)
	}

	out, _, err = forwarded(given, "exec.start", false)
	if err != nil || out.Get("Connection") != "" || out.Get("Upgrade") != "" {
		t.Errorf("not upgrading: %v %v", out, err)
	}

	// Upgrading, but the endpoint doesn't take an Upgrade header
	out, _, err = forwarded(given, "system.version", true)
	if err != nil || out.Get("Connection") != "" || out.Get("Upgrade") != "" {
		t.Errorf("not an upgrade endpoint: %v %v", out, err)
	}

	// The gate's Connection isn't the client's, so it isn't one not forwarded
	_, dropped, _ := forwarded(given, "exec.start", true)
	for _, name := range dropped {
		if name == "Connection" {
			t.Errorf("Connection logged as not forwarded")
		}
	}
}
