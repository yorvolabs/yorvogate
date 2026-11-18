package gate

import (
	"net/http"
	"testing"
)

// With a memory limit required, swap is bounded by it as Docker bounds it by default: memory and
// swap together at most twice the limit, never unlimited (-1). On create and on update; an update
// that gives swap alone is checked against the container's limit now.
func TestSwapIsBoundedByTheMemoryLimit(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	const memory = 512 << 20 // compose()'s

	for swap, want := range map[any]int{
		nil:            http.StatusOK, // Docker's default: as much swap as memory
		memory:         http.StatusOK, // no swap
		2 * memory:     http.StatusOK,
		2*memory + 1:   http.StatusForbidden,
		memory - 1:     http.StatusForbidden,
		-1:             http.StatusForbidden, // unlimited
		int64(1) << 40: http.StatusForbidden,
	} {
		body := set(compose(), "HostConfig.MemorySwap", swap)
		if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", encode(body), asJane); status != want {
			t.Errorf("create, MemorySwap %v: %d %s", swap, status, answer)
		}
	}

	for body, want := range map[string]int{
		`{"MemorySwap":-1}`:                             http.StatusForbidden,
		`{"MemorySwap":1073741824}`:                     http.StatusOK, // twice jane-php-1's 512 MiB
		`{"MemorySwap":1073741825}`:                     http.StatusForbidden,
		`{"Memory":268435456,"MemorySwap":536870912}`:   http.StatusOK,
		`{"Memory":268435456,"MemorySwap":1073741824}`:  http.StatusForbidden, // twice the new limit is 512 MiB
		`{"Memory":1073741824,"MemorySwap":2147483648}`: http.StatusOK,
	} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/update", body, asJane); status != want {
			t.Errorf("update %s: %d %s", body, status, answer)
		}
	}
}

// An update's limits are checked as a create's are, but what it leaves out is the container's own,
// which Docker keeps: an update of its restart policy alone is no update of its limits.
func TestAnUpdateLeavesWhatItOmits(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for body, want := range map[string]int{
		`{"RestartPolicy":{"Name":"always"}}`: http.StatusOK,
		`{}`:                                  http.StatusOK,
		`{"CPUShares":512}`:                   http.StatusOK,
		`{"Memory":0,"PidsLimit":null}`:       http.StatusOK, // both "no change", to Docker
		`{"PidsLimit":-1}`:                    http.StatusForbidden,
		`{"OomKillDisable":true}`:             http.StatusForbidden,
	} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/update", body, asJane); status != want {
			t.Errorf("update %s: %d %s", body, status, answer)
		}
	}
}
