package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// B, memory: a host of 10,000 images, 10 scopes of 10 each, and 10 filtered image lists at once (one
// per scope) through the token listener. Each makes Docker build its whole list: at 100 at once,
// Docker 29's containerd image store stopped answering before the gate's memory said anything. The gate reads Docker's list one image at a time and keeps
// only the scope's, so its memory should follow the scopes' lists, not the host's.

const (
	hostImages     = 10000
	imagesScopes   = 10
	imagesPerScope = 10
	concurrent     = 10
)

// loadImages loads the 10,000 images (sharing one small layer) straight into Docker.
func loadImages(d *http.Client, tmp string) (time.Duration, error) {
	layerPath, diffID, err := layer(tmp, 4096)
	if err != nil {
		return 0, err
	}

	images := make([]image, 0, hostImages)

	for s := range imagesScopes {
		for _, owner := range []string{"t" + scopeName(s), "s" + scopeName(s)} {
			for i := range imagesPerScope {
				images = append(images, image{config: config(diffID, owner+fmt.Sprint(i)), tags: []string{fmt.Sprintf("bench/%s/image%d:latest", owner, i)}})
			}
		}
	}

	for i := len(images); i < hostImages; i++ {
		images = append(images, image{config: config(diffID, fmt.Sprint("host", i)), tags: []string{fmt.Sprintf("bench/host/image%d:latest", i)}})
	}

	// In loads of loadBatch: one load of them all takes Docker more than 10 minutes
	started := time.Now()

	for from := 0; from < len(images); from += loadBatch {
		if err := loadArchive(d, tmp, layerPath, images[from:min(from+loadBatch, len(images))]); err != nil {
			return 0, err
		}

		progress("B: %d of %d images loaded, %v", min(from+loadBatch, len(images)), len(images), time.Since(started).Round(time.Second))
	}

	return time.Since(started), nil
}

const loadBatch = 500

// loadArchive loads images straight into Docker, in one archive.
func loadArchive(d *http.Client, tmp, layerPath string, images []image) error {
	path := filepath.Join(tmp, "images.tar")

	f, err := os.Create(path)
	if err != nil {
		return err
	}

	defer f.Close()

	if err := writeArchive(f, layerPath, images); err != nil {
		return err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "http://docker"+api+"/images/load?quiet=1", f)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-tar")

	res, err := d.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	answer, err := io.ReadAll(res.Body)
	if err == nil && (res.StatusCode != http.StatusOK || strings.Contains(string(answer), `"errorDetail"`)) {
		err = fmt.Errorf("loading %d images: %d %s", len(images), res.StatusCode, answer)
	}

	return err
}

func memory(o options, d *http.Client, loaded time.Duration) (*Memory, error) {
	g, configPath, err := writeGate(o, imagesScopes)
	if err != nil {
		return nil, err
	}

	if err := startGate(o, g, configPath); err != nil {
		return nil, err
	}

	defer g.stop()

	clients := make([]*http.Client, imagesScopes)
	for s := range clients {
		clients[s] = tokenClient(g.tcp, scopeName(s))
	}

	// One list each first: the connections open, and the gate warm
	for s, c := range clients {
		if _, err := listImages(tokenPath(c, "t"+scopeName(s)), 0); err != nil {
			return nil, err
		}
	}

	idle, _ := g.memory()
	idleHeap := g.heap()

	var peakHeap atomic.Int64

	sampling := make(chan struct{})

	var sampler sync.WaitGroup

	sampler.Go(func() {
		for {
			if h := g.heap(); h > peakHeap.Load() {
				peakHeap.Store(h)
			}

			select {
			case <-sampling:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})

	var (
		mu    sync.Mutex
		took  []time.Duration
		first error
	)

	const rounds = 10

	for range rounds {
		var wg sync.WaitGroup

		for s, c := range clients {
			for range concurrent / imagesScopes {
				wg.Go(func() {
					d, err := listImages(tokenPath(c, "t"+scopeName(s)), 0)

					mu.Lock()
					defer mu.Unlock()

					took = append(took, d)
					if err != nil && first == nil {
						first = err
					}
				})
			}
		}

		wg.Wait()
	}

	close(sampling)
	sampler.Wait()

	if first != nil {
		return nil, first
	}

	_, peak := g.memory()

	return &Memory{
		HostImages: hostImages, Scopes: imagesScopes, PerScope: imagesPerScope, Concurrent: concurrent, Rounds: rounds,
		LoadSeconds: loaded.Seconds(),
		IdleRSS:     mib(idle), PeakRSS: mib(peak), IdleHeap: mib(idleHeap), PeakHeap: mib(peakHeap.Load()),
		List: stats(took),
	}, nil
}

// tokenPath is a scope's path to the token listener, for listImages.
func tokenPath(c *http.Client, owner string) path {
	return path{name: "token", client: c, owner: owner}
}

func mib(b int64) float64 { return float64(b) / (1 << 20) }
