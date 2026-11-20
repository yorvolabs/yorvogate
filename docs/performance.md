# Performance

What YorvoGate adds to a request's time, how much memory it takes to list a large host's images, and how its cost grows with the number of scopes. Every number here comes from the benchmark in [`test/bench`](../test/bench/README.md), which anyone can run. It's re-run for each release.

## How it's measured

- **The machine** is CI's: GitHub's `ubuntu-26.04` runner, with the pinned Docker Engine on the containerd image store. Each run records the CPU model, the number of CPUs, the memory, the kernel and Docker's version beside its numbers, because the runner pool mixes CPU models. The machine line above each table says which one these came from.
- **Nothing crosses a network.** The client, YorvoGate and Docker are on one machine, over unix sockets or loopback TCP. A real deployment adds its own network time, the same with or without the gate.
- **Through YorvoGate, and straight to Docker, in the same run.** Each request is sent three ways in turn: through a scope's own socket, through a token listener, and straight to Docker's socket. The order rotates with each sample, so the machine's noise falls on each alike. A row's "added" is the gate's p50 minus Docker's, and "× Docker's" is the gate's p50 over Docker's.
- **Gate and Docker do the same work.** A scope's container list goes through the gate unfiltered, and the gate adds the scope's filter. The direct request gives Docker the same filter itself. A scope's image list isn't filtered on either side: the gate can't give Docker a filter, since a scope also sees the images in no protected namespace (such as `alpine`), so Docker builds its whole list either way. The image list's row is what the gate adds to that; on a host of many images, Docker's own list is most of a scope's wait.
- **The gate runs as in a small container:** with `GOMEMLIMIT=200MiB`, as [the image spool](configuration.md#the-image-spool) advises under a 256 MiB memory limit, with the per-scope [limits](configuration.md#limits) at their defaults, and with the policy of a site's containers that Quire Server uses (capabilities, no-new-privileges, ulimits, memory and pids), so a create is checked field by field.

## Results

The tables below are `results.md` from the full run at the release's commit.

<!-- Filled from CI's full run at the release commit: test/bench's results.md. -->

## What the numbers say

<!-- Written once CI's numbers are in. -->

## The regression gate

Every pull request runs the quick run, which leaves out B and the image requests, and samples less. It fails when a figure is past its threshold twice in a row, since a figure past it once is measured again. The night's full run is reported, never gated.

- **The overhead ratios** (A) are compared with [`test/bench/baseline.json`](../test/bench/baseline.json), the medians of three CI runs. A ratio more than 1.5 × its baseline's fails. A ratio is only gated where the gate is a visible share of the request's time: in the baseline, what the gate adds is at least 20% of Docker's p50. Where Docker's own work hides the gate (so far: a container list, a start, an exec), even a doubled check would sit inside the noise, so those rows are reported but not gated. A create is gated: the gate adds about a third to it, looking up the image, network and volume the body names. The table's last column says which rows are gated.
- **Scaling** (C) is held to fixed bounds, never to a baseline. A refused request's p50 at 10,000 scopes must be at most 1.5 × its p50 at 1 scope, on each listener. From 1,000 scopes to 10,000, `check` and `serve` may grow at most 1.5 × linearly (15 times as long). `check` at 10,000 scopes must take at most 30 seconds.
- **Only p50 is gated.** A regression in the tail (p99, the maximum) shows in the nightly full run's numbers, not as a failed pull request.
- **What the gate catches,** shown by breaking the gate on purpose: a 2 ms wait in every decision (the `_ping` and inspect ratios went from about 2–3 × Docker's time to 6 ×); a scope found by scanning them all (`check` grew 36 times from 1,000 scopes to 10,000, where it grows about 7.5 times); every pair of scopes compared (29 times). **What it doesn't:** a cost per request that grows by less than about half a request's time at 10,000 scopes. A scan of 10,000 scopes on every request adds about 0.15 ms, within the runner's noise; it's caught only where `check` does the same scan.

A change that's meant to move a gated figure updates `baseline.json` in the same pull request, from three CI runs' `bench` artifacts, and says why.
