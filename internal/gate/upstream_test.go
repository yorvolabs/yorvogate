package gate

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The API versions advertised are the ones both Docker and the gate serve: a Docker newer than the
// gate gives the gate's highest, so a client that negotiates (the CLI, Compose, buildx) asks for one
// the gate serves; an older Docker keeps its own, never one it can't serve, even below the gate's
// lowest (its clients are then refused by the gate, saying why). The minimum is the newer of the two.
func TestTheAdvertisedAPIVersionIsOneTheGateServes(t *testing.T) {
	for daemon, want := range map[string]string{"1.57": "1.56", "2.0": "1.56", "1.56": "1.56", "1.50": "1.50", "1.40": "1.40", "garbage": "garbage"} {
		d := startDocker(t)
		d.mu.Lock()
		d.api = daemon
		d.mu.Unlock()

		for _, listener := range []string{"server", "sites"} {
			server := gate(t, d, listener)
			header := map[string]string{"X-YorvoGate-Token": "secret"}
			if listener == "sites" {
				header = asJane
			}

			for _, method := range []string{"GET", "HEAD"} {
				req, _ := http.NewRequest(method, server.URL+"/_ping", nil)
				for k, v := range header {
					req.Header.Set(k, v)
				}

				res, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}

				_ = res.Body.Close()

				if got := res.Header.Get("Api-Version"); res.StatusCode != 200 || got != want {
					t.Errorf("Docker %s, %s, %s /_ping: %d, Api-Version %q, want %q", daemon, listener, method, res.StatusCode, got, want)
				}
			}

			status, answer := send(t, server, "GET", "/v1.44/version", "", header)

			var v struct {
				Version, ApiVersion, MinAPIVersion, Os string
				Components                             []struct {
					Name    string
					Details map[string]string
				}
			}

			if err := json.Unmarshal([]byte(answer), &v); status != 200 || err != nil {
				t.Fatalf("Docker %s, %s /version: %d %v", daemon, listener, status, err)
			}

			if v.ApiVersion != want || v.MinAPIVersion != "1.44" || v.Version != "30.0.0" || v.Os != "linux" ||
				len(v.Components) != 1 || v.Components[0].Details["ApiVersion"] != want || v.Components[0].Details["MinAPIVersion"] != "1.44" || v.Components[0].Details["Os"] != "linux" {
				t.Errorf("Docker %s, %s /version: %+v", daemon, listener, v)
			}
		}
	}
}

// Under the gate's lowest, Docker's own version is advertised, and a client that takes it is refused
// by the gate, saying why: no version is served by both.
func TestADockerOlderThanTheGate(t *testing.T) {
	d := startDocker(t)
	d.mu.Lock()
	d.api = "1.40"
	d.mu.Unlock()

	server := gate(t, d, "sites")

	if status, answer := send(t, server, "GET", "/v1.40/version", "", asJane); status != http.StatusBadRequest || !strings.Contains(message(t, answer), "API version 1.40 isn't supported (1.44 to 1.56)") {
		t.Errorf("%d %s", status, answer)
	}
}
