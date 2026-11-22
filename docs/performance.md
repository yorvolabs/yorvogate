# Performance

What YorvoGate adds to a request's time, how much memory it takes to list a large host's images, and how its cost grows with the number of scopes. Every number here comes from the benchmark in [`test/bench`](../test/bench/README.md), which anyone can run. It's re-run for each release.

## How it's measured

- **The machine** is CI's: GitHub's `ubuntu-26.04` runner, with the pinned Docker Engine on the containerd image store. Each run records the CPU model, the number of CPUs, the memory, the kernel and Docker's version beside its numbers, because the runner pool mixes CPU models. The machine line above each table says which one these came from.
- **Nothing crosses a network.** The client, YorvoGate and Docker are on one machine, over unix sockets or loopback TCP. A real deployment adds its own network time, the same with or without the gate.
- **Through YorvoGate, and straight to Docker, in the same run.** Each request is sent three ways in turn: through a scope's own socket, through a token listener, and straight to Docker's socket. The order rotates with each sample, so the machine's noise falls on each alike. A row's "added" is the gate's p50 minus Docker's, and "× Docker's" is the gate's p50 over Docker's.
- **Gate and Docker do the same work.** A scope's container list goes through the gate unfiltered, and the gate adds the scope's filter. The direct request gives Docker the same filter itself. A scope's image list isn't filtered on either side: the gate can't give Docker a filter, since a scope also sees the images in no protected namespace (such as `alpine`), so Docker builds its whole list either way. The image list's row is what the gate adds to that; on a host of many images, Docker's own list is most of a scope's wait.
- **The gate runs as in a small container:** with `GOMEMLIMIT=200MiB`, as [the image spool](configuration.md#the-image-spool) advises under a 256 MiB memory limit, with the per-scope [limits](configuration.md#limits) at their defaults, and with the policy of a site's containers that Quire Server uses (capabilities, no-new-privileges, ulimits, memory and pids), so a create is checked field by field.

## Results

The tables below are `results.md` from CI's full run on 0.4.0's code: commit 568480f, to which the release adds only documentation, a comment and the image's base digests.

Measured 2026-11-22 (full run) on INTEL(R) XEON(R) PLATINUM 8573C, 4 CPUs, 15982 MiB; Linux 7.0.0-1020-azure; Docker 29.10.0 (API 1.57, overlayfs, containerd); go1.27.4; YorvoGate dev (568480f0ed39).

### A. Latency, through YorvoGate and straight to Docker

| Request | Listener | Samples | Docker p50 / p99 | Through YorvoGate p50 / p99 | Added (p50) | × Docker's | Gated |
|---|---|---|---|---|---|---|---|
| `GET /_ping` | socket | 2000 | 155 µs / 262 µs | 351 µs / 779 µs | 196 µs | 2.27 | yes |
| `GET /_ping` | token | 2000 | 155 µs / 262 µs | 399 µs / 852 µs | 244 µs | 2.58 | yes |
| `GET /containers/json` | socket | 2000 | 38.98 ms / 43.18 ms | 39.27 ms / 43.91 ms | 292 µs | 1.01 | no |
| `GET /containers/json` | token | 2000 | 38.98 ms / 43.18 ms | 39.30 ms / 43.36 ms | 322 µs | 1.01 | no |
| `GET /containers/{id}/json` | socket | 2000 | 228 µs / 374 µs | 723 µs / 1.23 ms | 495 µs | 3.17 | yes |
| `GET /containers/{id}/json` | token | 2000 | 228 µs / 374 µs | 777 µs / 1.31 ms | 548 µs | 3.40 | yes |
| `POST /containers/create` | socket | 500 | 22.90 ms / 28.10 ms | 45.36 ms / 53.99 ms | 22.47 ms | 1.98 | yes |
| `POST /containers/create` | token | 500 | 22.90 ms / 28.10 ms | 45.31 ms / 54.66 ms | 22.41 ms | 1.98 | yes |
| `POST /containers/{id}/start` | socket | 500 | 86.26 ms / 109.27 ms | 86.97 ms / 97.70 ms | 707 µs | 1.01 | no |
| `POST /containers/{id}/start` | token | 500 | 86.26 ms / 109.27 ms | 87.13 ms / 95.17 ms | 863 µs | 1.01 | no |
| `exec: create, start, read` | socket | 300 | 40.16 ms / 44.76 ms | 42.14 ms / 49.68 ms | 1.98 ms | 1.05 | no |
| `exec: create, start, read` | token | 300 | 40.16 ms / 44.76 ms | 42.18 ms / 48.61 ms | 2.02 ms | 1.05 | no |
| `POST /images/load (1 GiB)` | socket | 5 | 8.91 s / 8.95 s | 11.04 s / 11.51 s | 2.13 s | 1.24 | no |
| `POST /images/load (1 GiB)` | token | 5 | 8.91 s / 8.95 s | 11.11 s / 11.65 s | 2.21 s | 1.25 | no |
| `GET /images/json` | socket | 20 | 16.43 s / 16.73 s | 16.47 s / 17.13 s | 44.11 ms | 1.00 | no |
| `GET /images/json` | token | 20 | 16.43 s / 16.73 s | 16.42 s / 16.87 s | −12.30 ms | 1.00 | no |

### B. Memory, 10 concurrent image lists on a host of 10000 images

10 scopes of 10 images each, 10 lists at once (1 per scope), 10 times. Docker loaded the 10000 images in 637 s.

| | Idle | Peak |
|---|---|---|
| Resident memory (VmRSS, VmHWM) | 16 MiB | 43 MiB |
| Go heap (`go_memstats_heap_alloc_bytes`) | 3.1 MiB | 14.0 MiB |

A list under that load: p50 97.55 s, p99 98.68 s.

### C. Scaling with scopes

| Scopes per listener | `check` | `serve`, every listener open | Refused request, token listener p50 / p99 | Refused request, scope socket p50 / p99 | Memory once up |
|---|---|---|---|---|---|
| 1 | 5.16 ms | 81.66 ms | 150 µs / 480 µs | 119 µs / 408 µs | 15 MiB |
| 100 | 8.00 ms | 82.91 ms | 160 µs / 766 µs | 131 µs / 892 µs | 23 MiB |
| 1000 | 41.30 ms | 163.56 ms | 154 µs / 788 µs | 124 µs / 662 µs | 41 MiB |
| 4000 | 146.91 ms | 352.08 ms | 155 µs / 575 µs | 124 µs / 376 µs | 96 MiB |
| 10000 | 364.78 ms | 787.12 ms | 162 µs / 431 µs | 124 µs / 351 µs | 188 MiB |

At 10000 scopes, a changed scope file was in effect 2.92 s after it was written (scope status, asked with its SHA-256).

## What the numbers say

- **Most requests cost Docker's time, not the gate's.** A container list, a start and an exec are within 5% of Docker's own time: Docker's work hides the gate's check. On a host of 10,000 images, a scope's image list takes about 16.4 s through the gate and straight to Docker alike; nearly all of it is Docker building its whole list.
- **The quick requests show the gate most.** `_ping` and a container inspect take Docker about 155 µs and 230 µs, and the gate adds 200 to 550 µs to them: 2.3 to 3.4 × Docker's time, but still under a millisecond.
- **A create costs the most: the gate adds about 22 ms to it, 2 × Docker's time.** Before Docker gets a create, the gate looks up what its body names, one call to Docker after another:
  - **the image,** by an image inspect. This is most of the added time. On the containerd image store, Docker works out an image's sizes for every inspect, which takes much longer than the other lookups. On one test machine the inspect took 370 ms of the 406 ms the gate added, against about 25 ms for each of the others.
  - **the container's name,** so a scope can't take one already in use;
  - **the networks and volumes** it would attach.

  The image lookup is the security check, and it can't be left out. Docker accepts an image ID prefix as short as four characters, so the gate resolves every image reference to its ID, refuses an image without a name the scope may use, and pins the create to that ID. There's no cheaper call: an image list filtered to one reference costs Docker about as much as the inspect. What a create costs through the gate therefore follows what an image inspect costs the host's Docker.

  For a site that's recreated a few times a day, the extra time is lost in the start that follows (a start is 86 ms here). A Compose project that creates many containers at once waits that long for each.
- **An image load waits for the disk.** The gate keeps a scope's archive in [the image spool](configuration.md#the-image-spool) and checks it whole before Docker gets any of it, so a 1 GiB load takes about 2 s longer here (1.24 × Docker's time): the disk's time to write the archive and read it again. It follows the disk: on CI's runners it ranged from 0.14 s to 2.5 s.
- **Memory follows the scopes' lists, not the host's.** With 10 image lists at once on a host of 10,000 images, the gate peaked at 43 MiB of resident memory (14 MiB of heap), from 16 MiB idle. It reads Docker's list one image at a time and keeps only the scope's.
- **The number of scopes barely moves a request.** A refused request takes 0.15 ms at 1 scope and 0.16 ms at 10,000, on a token listener (0.12 ms on a scope's socket at both). Loading the scopes is what grows: `check` takes 365 ms at 10,000 scopes, `serve` is ready in 0.8 s, and a changed scope file is in effect 2.9 s after it's written, the 2-second scan included.

## The regression gate

Every pull request runs the quick run, which leaves out B and the image requests, and samples less. It fails when a figure is past its threshold twice in a row, since a figure past it once is measured again. The night's full run is reported, never gated.

- **The overhead ratios** (A) are compared with [`test/bench/baseline.json`](../test/bench/baseline.json), the medians of three CI runs. A ratio more than 1.5 × its baseline's fails. A ratio is only gated where the gate is a visible share of the request's time: in the baseline, what the gate adds is at least 20% of Docker's p50. Where Docker's own work hides the gate (so far: a container list, a start, an exec), even a doubled check would sit inside the noise, so those rows are reported but not gated. A create is gated: the gate nearly doubles it, looking up the image, network and volume the body names. The table's last column says which rows are gated.
- **Scaling** (C) is held to fixed bounds, never to a baseline. A refused request's p50 at 10,000 scopes must be at most 1.5 × its p50 at 1 scope, on each listener. From 1,000 scopes to 10,000, `check` and `serve` may grow at most 1.5 × linearly (15 times as long). `check` at 10,000 scopes must take at most 30 seconds.
- **Only p50 is gated.** A regression in the tail (p99, the maximum) shows in the nightly full run's numbers, not as a failed pull request.
- **What the gate catches,** shown by breaking the gate on purpose: a 2 ms wait in every decision (the `_ping` and inspect ratios went from about 2–3 × Docker's time to 6 ×); a scope found by scanning them all (`check` grew 36 times from 1,000 scopes to 10,000, where it grows about 7.5 times); every pair of scopes compared (29 times). **What it doesn't:** a cost per request that grows by less than about half a request's time at 10,000 scopes. A scan of 10,000 scopes on every request adds about 0.15 ms, within the runner's noise; it's caught only where `check` does the same scan.

A change that's meant to move a gated figure updates `baseline.json` in the same pull request, from three CI runs' `bench` artifacts, and says why.
