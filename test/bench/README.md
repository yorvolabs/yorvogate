# The benchmark

What YorvoGate adds to a request's time, how much memory it takes for a host's image list, and how its cost grows with scopes. It runs the built gate in front of a real Docker, and measures each request through the gate and straight to Docker in the same run. The published numbers, and what they include, are in [docs/performance.md](../../docs/performance.md).

It's a module of its own, standard library only, so YorvoGate's `go test ./...` never runs it. `make check` vets and builds it (the `bench` target).

## Running it

On any Linux with Docker, Go and a built gate:

```
make build
cd test/bench
go run . -gate ../../bin/yorvogate -docker /var/run/docker.sock
```

- `-full` is the full run: more samples, scopes at 1, 100, 1,000, 4,000 and 10,000, a 1 GiB image load, and B's 10,000 images. It takes hours, most of them Docker's: on an 8-CPU Ubuntu machine, the measuring took about 2 hours (33 minutes of it loading the 10,000 images), and removing them about 2 more. It needs about 3 GiB of disk beside Docker's. Without it, the quick run takes a few minutes: A without the image requests, and C at 1, 1,000 and 10,000 scopes.
- `-out` is where `results.json` and `results.md` go (`out/` by default).
- `-leave` leaves what the run made in Docker when it ends, skipping that removal. It's for a machine that's thrown away after, such as CI's runner: CI's full run passes it.
- `-without-lsm` lets the gate accept a Docker without AppArmor or SELinux, such as Docker Desktop's.
- `-baseline baseline.json` compares the run with the baseline, and marks which figures are gated. `-fail` makes a regression fail the run. CI's pull-request run gives both.

It acts on Docker as a client would. It pulls `alpine:3.22`, and creates containers, networks, volumes and images, all with the label `org.yorvolabs.bench` or named `bench/…`. What it makes straight with Docker also carries `org.yorvolabs.project=yorvogate`. It removes them before it starts and when it ends. So run it on a Docker you can spare: a test machine, or CI's runner.

## What it measures

- **A, latency.** Each request is sent through a scope's socket, through the token listener, and straight to Docker, the three in turn with the order rotating, so the machine's noise falls on each alike. Each row gives p50 and p99 of each, what the gate adds at p50, and the gate's p50 as a multiple of Docker's.
- **B, memory** (full run). Docker holds 10,000 images. Ten scopes of ten images each list theirs, all ten at once, ten times. B gives the gate's resident memory (VmRSS, and VmHWM at its peak) and its Go heap, read from the admin listener's `go_memstats_heap_alloc_bytes`.
- **C, scaling.** The gate with 1 to 10,000 scopes on each of two scoped listeners. It times `check` and `serve` (until every listener and socket is open), and records the memory once up. Up to 100 scopes, spread over them all, send in turn a request they may not make, decided without Docker, on a token listener and on their own sockets, each over a kept connection, so the timing is the gate's work and not a connection's opening. At the most scopes, it also times how long a changed scope file takes to be in effect.

The gate runs with `GOMEMLIMIT=200MiB`, as the configuration guide advises under a 256 MiB memory limit.

## The regression gate

A pull request's CI runs the quick run with `-baseline baseline.json -fail`. A figure past its threshold is measured again, and fails only if it's past it twice. Both measurements are logged.

- **A's ratios**, against `baseline.json`: a ratio more than 1.5 × the baseline's fails. The gate's p50 over Docker's, both from the same run, cancels most of a shared runner's noise. Only rows where the gate is a visible share of the time are gated: where, in the baseline, what the gate adds is at least 20% of Docker's p50. Where Docker's own work hides the gate (so far: a container list, a start, an exec), a regression wouldn't show above the noise, so those rows are reported, not gated. `results.md` says which rows are gated.
- **C's scaling**, absolutely: the p50 of a refused request at 10,000 scopes must be at most 1.5 × its p50 at 1 scope, on each listener. This is never compared against the baseline, so "flat" stays the rule, not whatever a run measured.
- **`check` and `serve` grow at most 1.5 × linearly**: from 1,000 scopes to 10,000, each may take at most 15 times as long. A cost that grows with every pair of scopes, or a scope found by a scan of them all, shows here first.
- **`check` at 10,000 scopes**: at most 30 seconds.

Only p50 is gated, so a regression in the tail shows only in the full run's p99. The per-request bound fails a cost that grows with scopes by about half a request's time or more at 10,000 scopes (0.2's grew by 51 ms). A smaller one, such as a scan of 10,000 scopes on every request (about 0.15 ms), is within a shared runner's noise there: it's caught by the growth bound where `check` does the same scan, and only then.

`baseline.json` is the medians of three CI runs. It changes only in a pull request that says why, from those runs' `results.json` (CI keeps them as the run's `bench` artifact):

```
go run . -baseline-of run1/results.json,run2/results.json,run3/results.json > baseline.json
```
