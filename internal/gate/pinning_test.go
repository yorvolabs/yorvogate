package gate

import (
	"net/http"
	"strings"
	"testing"
)

// A container that joins another of its scope's containers (its PIDs, IPC, network, or volumes) names
// it to Docker by the ID the gate checked, not the name it was asked by: by then, the name could be
// another container's (a rename, or a remove and create).
func TestJoiningAnotherContainerIsByItsID(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for field, value := range map[string]any{
		"HostConfig.PidMode":     "container:jane-php-1",
		"HostConfig.IpcMode":     "container:jane-php-1",
		"HostConfig.VolumesFrom": []any{"jane-php-1:ro"},
	} {
		body := set(compose(), field, value)
		if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-worker-1", encode(body), asJane); status != http.StatusOK {
			t.Fatalf("%s %v: %d %s", field, value, status, answer)
		}

		forwarded := d.last().body
		if strings.Contains(forwarded, "jane-php-1") || !strings.Contains(forwarded, janePHP) {
			t.Errorf("%s %v: forwarded %s, want it by its ID", field, value, forwarded)
		}
	}

	// The network too, which then joins none of its own
	body := set(set(compose(), "HostConfig.NetworkMode", "container:jane-php-1"), "NetworkingConfig", nil)
	if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-worker-1", encode(body), asJane); status != http.StatusOK {
		t.Fatalf("NetworkMode: %d %s", status, answer)
	}

	if forwarded := d.last().body; strings.Contains(forwarded, "container:jane-php-1") || !strings.Contains(forwarded, `"NetworkMode":"container:`+janePHP+`"`) {
		t.Errorf("NetworkMode: forwarded %s, want it by its ID", forwarded)
	}
}
