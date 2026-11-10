package gate

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

// A scope's /info and /version are an allow-list of Docker's answer: what clients read (Compose its
// swarm state, buildx --load its image store; moby 29.9.2's clients otherwise only print), and what
// says nothing of the host or of other scopes. A field Docker adds isn't in it. Its counts are the
// scope's own. What's left out: the host's name, Docker's configuration (its root, proxies, registry
// configuration, labels, address pools, plugins and runtimes beyond the scope's), other scopes'
// activity (the whole host's counts), and the versions of containerd, runc and docker-init. (The
// kernel, CPUs and memory are left out too, though a scope's container reads them from the kernel.)

// infoFields are kept as Docker answers them.
var infoFields = []string{
	"ServerVersion", "OSType", "Architecture", "Driver", "IndexServerAddress", "ExperimentalBuild",
	"LiveRestoreEnabled", "CgroupDriver", "CgroupVersion", "DefaultRuntime", "LoggingDriver", "Isolation",
	"MemoryLimit", "SwapLimit", "KernelMemoryTCP", "CpuCfsPeriod", "CpuCfsQuota", "CPUShares", "CPUSet",
	"PidsLimit", "OomKillDisable", "IPv4Forwarding", "Debug", "SystemTime",
}

// versionFields are kept of /version, and of its Engine component's details.
var versionFields = []string{"Version", "ApiVersion", "MinAPIVersion", "Os", "Arch", "Experimental", "Platform"}

func keep(from map[string]json.RawMessage, fields []string) map[string]json.RawMessage {
	kept := map[string]json.RawMessage{}

	for _, f := range fields {
		if v, ok := from[f]; ok {
			kept[f] = v
		}
	}

	return kept
}

// info filters /info for the scope.
func (s *scoped) info(body []byte) ([]byte, error) {
	var docker map[string]json.RawMessage
	if err := json.Unmarshal(body, &docker); err != nil {
		return nil, err
	}

	answer := keep(docker, infoFields)

	// Which image store: buildx --load reads it (driver-type io.containerd.snapshotter.v1)
	var status [][2]string
	_ = json.Unmarshal(docker["DriverStatus"], &status)
	store := [][2]string{}
	for _, st := range status {
		if st[0] == "driver-type" {
			store = append(store, st)
		}
	}

	answer["DriverStatus"], _ = json.Marshal(store)

	// Compose reads anything but inactive (or locked) as swarm enabled; a scope has no swarm.
	answer["Swarm"], _ = json.Marshal(map[string]string{"LocalNodeState": "inactive"})

	answer["SecurityOptions"], _ = json.Marshal(securityOptions(docker["SecurityOptions"]))
	answer["Plugins"], _ = json.Marshal(map[string][]string{
		"Volume": {"local"}, "Network": {"bridge"},
		"Log": append([]string{"json-file", "local", "none"}, s.policy.LogDrivers...),
	})

	runtimes := map[string]map[string]string{"runc": {}}
	for _, r := range s.policy.Runtimes {
		runtimes[r] = map[string]string{}
	}

	answer["Runtimes"], _ = json.Marshal(runtimes)

	counts, err := s.counts()
	if err != nil {
		return nil, err
	}

	for k, v := range counts {
		answer[k], _ = json.Marshal(v)
	}

	return json.Marshal(answer)
}

// securityOptions are /info's, each with its name, and its profile only when that's Docker's own
// ("builtin", "default") or "unconfined": a profile from a file names a path of the host's.
func securityOptions(raw json.RawMessage) []string {
	var options []string
	_ = json.Unmarshal(raw, &options)

	kept := []string{}

	for _, o := range options {
		fields := securityOption(o)
		entry := "name=" + fields["name"]

		if p := fields["profile"]; slices.Contains([]string{"builtin", "default", "unconfined"}, p) {
			entry += ",profile=" + p
		}

		kept = append(kept, entry)
	}

	return kept
}

// counts are the scope's own containers, by state, and the images it may see.
func (s *scoped) counts() (map[string]int, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {s.scope.Owner.Key + "=" + s.scope.Owner.Value}})

	var containers []struct {
		Names []string
		State string
	}
	if _, err := s.docker.fetch(s.ctx, s.version, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &containers); err != nil {
		return nil, err
	}

	counts := map[string]int{"Containers": 0, "ContainersRunning": 0, "ContainersPaused": 0, "ContainersStopped": 0, "Images": 0}

	for _, c := range containers {
		// A builder is the orchestrator's, whatever its labels
		if slices.ContainsFunc(c.Names, func(n string) bool { return s.scope.Builds(strings.TrimPrefix(n, "/")) }) {
			continue
		}

		counts["Containers"]++

		switch strings.ToLower(c.State) {
		case "running", "restarting":
			counts["ContainersRunning"]++
		case "paused":
			counts["ContainersPaused"]++
		default:
			counts["ContainersStopped"]++
		}
	}

	var images []struct{ RepoTags []string }
	if _, err := s.docker.fetch(s.ctx, s.version, "/images/json", &images); err != nil {
		return nil, err
	}

	for _, img := range images {
		if len(s.visible(img.RepoTags)) > 0 {
			counts["Images"]++
		}
	}

	return counts, nil
}

// version filters /version for the scope: Docker's own version and platform, and its Engine
// component, without the kernel's, build details, or other components' versions.
func (s *scoped) versionAnswer(body []byte) ([]byte, error) {
	var docker map[string]json.RawMessage
	if err := json.Unmarshal(body, &docker); err != nil {
		return nil, err
	}

	answer := keep(docker, versionFields)

	var components []map[string]json.RawMessage
	_ = json.Unmarshal(docker["Components"], &components)
	engines := []map[string]json.RawMessage{}

	for _, c := range components {
		var name string
		if json.Unmarshal(c["Name"], &name) != nil || name != "Engine" {
			continue
		}

		var details map[string]json.RawMessage
		_ = json.Unmarshal(c["Details"], &details)

		engine := keep(c, []string{"Name", "Version"})
		engine["Details"], _ = json.Marshal(keep(details, versionFields))
		engines = append(engines, engine)
	}

	answer["Components"], _ = json.Marshal(engines)

	return json.Marshal(answer)
}

// infoOfItsOwn and versionOfItsOwn: Docker's answers, filtered.
func (s *scoped) infoOfItsOwn() error {
	s.answer = s.info

	return nil
}

func (s *scoped) versionOfItsOwn() error {
	s.answer = s.versionAnswer

	return nil
}
