package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// call sends one request and reads its whole answer.
func call(c *http.Client, method, path string, body any) (int, []byte, error) {
	var reader io.Reader

	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	default:
		encoded, err := json.Marshal(b)
		if err != nil {
			return 0, nil, err
		}

		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, "http://docker"+path, reader)
	if err != nil {
		return 0, nil, err
	}

	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}

	defer res.Body.Close()

	answer, err := io.ReadAll(res.Body)

	return res.StatusCode, answer, err
}

// must is call, an answer outside 2xx an error.
func must(c *http.Client, method, path string, body any) ([]byte, error) {
	status, answer, err := call(c, method, path, body)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}

	if status/100 != 2 {
		return nil, fmt.Errorf("%s %s: %d %s", method, path, status, bytes.TrimSpace(answer))
	}

	return answer, nil
}

// The image every container runs: pulled once, and tagged into each measured scope's namespace.
const baseImage = "alpine:3.22"

func pullBase(d *http.Client) error {
	if status, _, err := call(d, "GET", api+"/images/"+baseImage+"/json", nil); err == nil && status == http.StatusOK {
		return nil
	}

	repo, tag, _ := strings.Cut(baseImage, ":")
	answer, err := must(d, "POST", api+"/images/create?fromImage="+repo+"&tag="+tag, nil)

	if err == nil && bytes.Contains(answer, []byte(`"errorDetail"`)) {
		err = fmt.Errorf("pulling %s: %s", baseImage, answer)
	}

	return err
}

// createContainer creates a container of owner's (the host's: no scope's), running sleep, straight
// with Docker.
func createContainer(d *http.Client, owner, name string) (string, error) {
	image := baseImage
	if owner != "host" {
		image = "bench/" + owner + "/alpine"
	}

	answer, err := must(d, "POST", api+"/containers/create?name="+name, map[string]any{
		"Image":  image,
		"Cmd":    []string{"sleep", "86400"},
		"Labels": map[string]string{ownerLabel: owner},
	})
	if err != nil {
		return "", err
	}

	var created struct {
		ID string `json:"Id"`
	}

	return created.ID, json.Unmarshal(answer, &created)
}

// composeBody is a container create as Compose sends it for a site's service: what the gate checks
// field by field.
func composeBody(owner string) map[string]any {
	return map[string]any{
		"Image":  "bench/" + owner + "/alpine",
		"Cmd":    []string{"sleep", "86400"},
		"Labels": map[string]string{ownerLabel: owner, "com.docker.compose.project": owner, "com.docker.compose.service": "php"},
		"Env":    []string{"SERVER_NAME=" + owner + ".example"},
		"HostConfig": map[string]any{
			"NetworkMode":   owner + "_default",
			"CapDrop":       []string{"ALL"},
			"CapAdd":        []string{"NET_BIND_SERVICE"},
			"SecurityOpt":   []string{"no-new-privileges:true"},
			"Memory":        536870912,
			"PidsLimit":     256,
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
			"LogConfig":     map[string]any{"Type": "json-file", "Config": map[string]any{}},
			"Mounts":        []any{map[string]any{"Type": "volume", "Source": owner + "_data", "Target": "/data", "VolumeOptions": map[string]any{}}},
			"Tmpfs":         map[string]string{"/tmp": ""},
			"Ulimits":       []any{map[string]any{"Name": "nofile", "Soft": 1024, "Hard": 2048}},
		},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{
			owner + "_default": map[string]any{"Aliases": []string{"php"}},
		}},
	}
}

// prepareOwner gives a measured scope its image, network and volume, 20 containers and one running.
func prepareOwner(d *http.Client, owner string) (running string, err error) {
	if _, err := must(d, "POST", api+"/images/"+baseImage+"/tag?repo=bench/"+owner+"/alpine&tag=latest", nil); err != nil {
		return "", err
	}

	labels := map[string]string{ownerLabel: owner}

	if _, err := must(d, "POST", api+"/networks/create", map[string]any{"Name": owner + "_default", "Labels": labels}); err != nil {
		return "", err
	}

	if _, err := must(d, "POST", api+"/volumes/create", map[string]any{"Name": owner + "_data", "Labels": labels}); err != nil {
		return "", err
	}

	for i := range 20 {
		if _, err := createContainer(d, owner, fmt.Sprintf("%s-l%02d", owner, i)); err != nil {
			return "", err
		}
	}

	running, err = createContainer(d, owner, owner+"-run")
	if err != nil {
		return "", err
	}

	_, err = must(d, "POST", api+"/containers/"+running+"/start", nil)

	return running, err
}

// clean removes what any run left: every container, network and volume with the owner label, and
// every image named bench/….
func clean(d *http.Client) error {
	filter := url.QueryEscape(`{"label":["` + ownerLabel + `"]}`)

	var listed []struct {
		ID string `json:"Id"`
	}

	answer, err := must(d, "GET", api+"/containers/json?all=1&filters="+filter, nil)
	if err == nil {
		err = json.Unmarshal(answer, &listed)
	}

	if err != nil {
		return err
	}

	ids := make([]string, 0, len(listed))
	for _, c := range listed {
		ids = append(ids, c.ID)
	}

	if err := parallel(ids, func(id string) error {
		_, err := must(d, "DELETE", api+"/containers/"+id+"?force=1&v=1", nil)

		return err
	}); err != nil {
		return err
	}

	for _, kind := range []string{"networks", "volumes"} {
		answer, err := must(d, "GET", api+"/"+kind+"?filters="+filter, nil)
		if err != nil {
			return err
		}

		var names []string

		if kind == "networks" {
			var networks []struct{ Name string }
			_ = json.Unmarshal(answer, &networks)

			for _, n := range networks {
				names = append(names, n.Name)
			}
		} else {
			var volumes struct{ Volumes []struct{ Name string } }
			_ = json.Unmarshal(answer, &volumes)

			for _, v := range volumes.Volumes {
				names = append(names, v.Name)
			}
		}

		for _, name := range names {
			if _, err := must(d, "DELETE", api+"/"+kind+"/"+name, nil); err != nil {
				return err
			}
		}
	}

	return removeImages(d, "bench/*/*")
}

// removeImages removes every image a reference matches, by ID (an image of many names, at once).
func removeImages(d *http.Client, reference string) error {
	answer, err := must(d, "GET", api+"/images/json?filters="+url.QueryEscape(`{"reference":["`+reference+`"]}`), nil)
	if err != nil {
		return err
	}

	var images []struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(answer, &images); err != nil {
		return err
	}

	ids := make([]string, 0, len(images))
	for _, i := range images {
		ids = append(ids, i.ID)
	}

	return parallel(ids, func(id string) error {
		status, answer, err := call(d, "DELETE", api+"/images/"+id+"?force=1&noprune=0", nil)
		if err == nil && status/100 != 2 && status != http.StatusNotFound {
			err = fmt.Errorf("removing image %s: %d %s", id, status, answer)
		}

		return err
	})
}

// parallel runs do on each item, 8 at once, and returns the first error.
func parallel(items []string, do func(string) error) error {
	work := make(chan string)

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)

	for range 8 {
		wg.Go(func() {
			for item := range work {
				if err := do(item); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
				}
			}
		})
	}

	for _, item := range items {
		work <- item
	}

	close(work)
	wg.Wait()

	return first
}
