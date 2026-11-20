package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

// C, scaling: the gate with 1 to 10,000 scopes on each scoped listener. A request's cost is that of
// one the scope may not make (decided without Docker, so only the gate's own work is timed), from
// scopes in turn on kept connections, on the token listener and on scope sockets;
// check's and serve's time to start; the memory once up; and at the most scopes, how long until a
// changed scope file is in effect.

func scaling(o options, counts []int, samples int) ([]Scaling, *Rescan, error) {
	var (
		rows   []Scaling
		rescan *Rescan
	)

	for _, n := range counts {
		row, r, err := scale(o, n, samples, n == counts[len(counts)-1])
		if err != nil {
			return nil, nil, err
		}

		rows = append(rows, row)
		if r != nil {
			rescan = r
		}

		progress("C %5d scopes: check %v, serve %v, tokens p50 %s, sockets p50 %s, RSS %.0f MiB", n, ms(row.CheckMS), ms(row.ServeMS), us(row.Tokens.P50), us(row.Sockets.P50), row.RSS)
	}

	return rows, rescan, nil
}

func scale(o options, n, samples int, withRescan bool) (Scaling, *Rescan, error) {
	g, path, err := writeGate(o, n)
	if err != nil {
		return Scaling{}, nil, err
	}

	checked, err := check(o, path)
	if err != nil {
		g.stop()

		return Scaling{}, nil, err
	}

	if err := startGate(o, g, path); err != nil {
		return Scaling{}, nil, err
	}

	defer g.stop()

	tokens, err := refusals(g, samples, func(name string) *http.Client { return tokenClient(g.tcp, name) })
	if err != nil {
		return Scaling{}, nil, fmt.Errorf("%d scopes, tokens: %w", n, err)
	}

	sockets, err := refusals(g, samples, func(name string) *http.Client {
		return unixClient(filepath.Join(g.dir, "sockets", name+".sock"))
	})
	if err != nil {
		return Scaling{}, nil, fmt.Errorf("%d scopes, sockets: %w", n, err)
	}

	rss, _ := g.memory()
	row := Scaling{Scopes: n, Samples: samples, CheckMS: float64(checked.Microseconds()) / 1000, ServeMS: float64(g.took.Microseconds()) / 1000, Tokens: tokens, Sockets: sockets, RSS: mib(rss)}

	if !withRescan {
		return row, nil, nil
	}

	r, err := rescanOne(g)

	return row, r, err
}

// spread is how many scopes a request's cost is measured from: up to 100, spread over them all.
const spread = 100

// refusals times samples refused requests (GET /swarm: scope.endpoint-not-allowed, decided without
// Docker), from up to spread scopes in turn, each on a connection of its own that's kept: only the
// gate's work is timed, not a connection's opening.
func refusals(g *gate, samples int, client func(name string) *http.Client) (Stats, error) {
	k := min(g.scopes, spread)

	clients := make([]*http.Client, k)
	for i := range clients {
		clients[i] = client(scopeName(i * g.scopes / k))
	}

	took := make([]time.Duration, 0, samples)

	// One round first: every connection open
	for i := -k; i < samples; i++ {
		c := clients[(i+k)%k]

		started := time.Now()

		status, _, err := call(c, "GET", api+"/swarm", nil)
		if err != nil {
			return Stats{}, err
		}

		if status != http.StatusForbidden {
			return Stats{}, fmt.Errorf("a refused request answered %d", status)
		}

		if i >= 0 {
			took = append(took, time.Since(started))
		}
	}

	return stats(took), nil
}

// rescanOne changes one scope file of the scope sockets' listener, and times until scope status says
// the new file is in effect.
func rescanOne(g *gate) (*Rescan, error) {
	name := scopeName(g.scopes / 2)
	trusted := &http.Client{Timeout: time.Minute, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", g.trusted)
		},
	}}

	started := time.Now()

	// The same claims, a field more: a file that's changed, and still valid
	sum, err := writeScopeFile(g.dir, "socket-scopes", name, "s"+name, "", `, "builders": []`)
	if err != nil {
		return nil, err
	}

	status, answer, err := call(trusted, "GET", "/_yorvogate/v1/scopes/"+name+"?listener=sockets&sha256="+sum, nil)
	if err != nil {
		return nil, err
	}

	took := time.Since(started)

	if status != http.StatusOK {
		return nil, fmt.Errorf("scope status after a rescan: %d %s", status, answer)
	}

	return &Rescan{Scopes: g.scopes, MS: float64(took.Microseconds()) / 1000}, nil
}
