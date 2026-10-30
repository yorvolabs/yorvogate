package route

import "strings"

// The endpoints of the Docker Engine API 1.56 (github.com/moby/moby/api's swagger.yaml), by group.
// Fixed paths come before patterns that could also match them ("/images/json" before
// "/images/{name*}/json"): the first match wins.
var table = func() []Endpoint {
	read := func(name, method, pattern string, group Group) Endpoint {
		return Endpoint{Name: name, Method: method, Pattern: pattern, Group: group}
	}
	write := func(name, method, pattern string, group Group) Endpoint {
		return Endpoint{Name: name, Method: method, Pattern: pattern, Group: group, Write: true}
	}
	upgrade := func(e Endpoint) Endpoint { e.Upgrade = true; return e }
	stream := func(e Endpoint) Endpoint { e.Stream = true; return e }

	endpoints := []Endpoint{
		// System
		read("system.ping", "GET", "/_ping", System),
		read("system.ping", "HEAD", "/_ping", System),
		read("system.version", "GET", "/version", System),
		read("system.info", "GET", "/info", System),
		read("system.events", "GET", "/events", System),
		read("system.df", "GET", "/system/df", System),
		write("system.auth", "POST", "/auth", System),

		// Containers
		read("container.list", "GET", "/containers/json", Containers),
		write("container.create", "POST", "/containers/create", Containers),
		write("container.prune", "POST", "/containers/prune", Containers),
		read("container.inspect", "GET", "/containers/{id}/json", Containers),
		read("container.top", "GET", "/containers/{id}/top", Containers),
		read("container.logs", "GET", "/containers/{id}/logs", Containers),
		read("container.changes", "GET", "/containers/{id}/changes", Containers),
		read("container.export", "GET", "/containers/{id}/export", Containers),
		read("container.stats", "GET", "/containers/{id}/stats", Containers),
		write("container.resize", "POST", "/containers/{id}/resize", Containers),
		write("container.start", "POST", "/containers/{id}/start", Containers),
		write("container.stop", "POST", "/containers/{id}/stop", Containers),
		write("container.restart", "POST", "/containers/{id}/restart", Containers),
		write("container.kill", "POST", "/containers/{id}/kill", Containers),
		write("container.update", "POST", "/containers/{id}/update", Containers),
		write("container.rename", "POST", "/containers/{id}/rename", Containers),
		write("container.pause", "POST", "/containers/{id}/pause", Containers),
		write("container.unpause", "POST", "/containers/{id}/unpause", Containers),
		upgrade(write("container.attach", "POST", "/containers/{id}/attach", Containers)),
		upgrade(write("container.attach-websocket", "GET", "/containers/{id}/attach/ws", Containers)),
		write("container.wait", "POST", "/containers/{id}/wait", Containers),
		write("container.delete", "DELETE", "/containers/{id}", Containers),
		read("container.archive-info", "HEAD", "/containers/{id}/archive", Containers),
		read("container.archive-get", "GET", "/containers/{id}/archive", Containers),
		stream(write("container.archive-put", "PUT", "/containers/{id}/archive", Containers)),
		write("container.commit", "POST", "/commit", Images),

		// Exec
		write("exec.create", "POST", "/containers/{id}/exec", Exec),
		// An upgrade when it attaches; a detached exec ("docker exec -d") is a plain request.
		write("exec.start", "POST", "/exec/{id}/start", Exec),
		write("exec.resize", "POST", "/exec/{id}/resize", Exec),
		read("exec.inspect", "GET", "/exec/{id}/json", Exec),

		// Images (fixed paths first)
		read("image.list", "GET", "/images/json", Images),
		stream(write("image.create", "POST", "/images/create", Images)),
		read("image.search", "GET", "/images/search", Images),
		write("image.prune", "POST", "/images/prune", Images),
		read("image.save-many", "GET", "/images/get", Images),
		stream(write("image.load", "POST", "/images/load", Images)),
		read("image.inspect", "GET", "/images/{name*}/json", Images),
		read("image.history", "GET", "/images/{name*}/history", Images),
		write("image.push", "POST", "/images/{name*}/push", Images),
		write("image.tag", "POST", "/images/{name*}/tag", Images),
		read("image.save", "GET", "/images/{name*}/get", Images),
		write("image.delete", "DELETE", "/images/{name*}", Images),

		// Build
		stream(write("build.build", "POST", "/build", Build)),
		write("build.prune", "POST", "/build/prune", Build),
		write("build.cancel", "POST", "/build/cancel", Build),

		// Networks
		read("network.list", "GET", "/networks", Networks),
		write("network.create", "POST", "/networks/create", Networks),
		write("network.prune", "POST", "/networks/prune", Networks),
		read("network.inspect", "GET", "/networks/{id}", Networks),
		write("network.delete", "DELETE", "/networks/{id}", Networks),
		write("network.connect", "POST", "/networks/{id}/connect", Networks),
		write("network.disconnect", "POST", "/networks/{id}/disconnect", Networks),

		// Volumes
		read("volume.list", "GET", "/volumes", Volumes),
		write("volume.create", "POST", "/volumes/create", Volumes),
		write("volume.prune", "POST", "/volumes/prune", Volumes),
		read("volume.inspect", "GET", "/volumes/{name}", Volumes),
		write("volume.update", "PUT", "/volumes/{name}", Volumes),
		write("volume.delete", "DELETE", "/volumes/{name}", Volumes),

		// Distribution
		read("distribution.inspect", "GET", "/distribution/{name*}/json", Distribution),

		// Plugins
		read("plugin.list", "GET", "/plugins", Plugins),
		read("plugin.privileges", "GET", "/plugins/privileges", Plugins),
		write("plugin.pull", "POST", "/plugins/pull", Plugins),
		write("plugin.create", "POST", "/plugins/create", Plugins),
		read("plugin.inspect", "GET", "/plugins/{name*}/json", Plugins),
		write("plugin.delete", "DELETE", "/plugins/{name*}", Plugins),
		write("plugin.enable", "POST", "/plugins/{name*}/enable", Plugins),
		write("plugin.disable", "POST", "/plugins/{name*}/disable", Plugins),
		write("plugin.upgrade", "POST", "/plugins/{name*}/upgrade", Plugins),
		write("plugin.push", "POST", "/plugins/{name*}/push", Plugins),
		write("plugin.set", "POST", "/plugins/{name*}/set", Plugins),

		// Swarm, its services, nodes, tasks, secrets and configs
		read("swarm.inspect", "GET", "/swarm", Swarm),
		write("swarm.init", "POST", "/swarm/init", Swarm),
		write("swarm.join", "POST", "/swarm/join", Swarm),
		write("swarm.leave", "POST", "/swarm/leave", Swarm),
		write("swarm.update", "POST", "/swarm/update", Swarm),
		read("swarm.unlockkey", "GET", "/swarm/unlockkey", Swarm),
		write("swarm.unlock", "POST", "/swarm/unlock", Swarm),
		read("node.list", "GET", "/nodes", Swarm),
		read("node.inspect", "GET", "/nodes/{id}", Swarm),
		write("node.delete", "DELETE", "/nodes/{id}", Swarm),
		write("node.update", "POST", "/nodes/{id}/update", Swarm),
		read("service.list", "GET", "/services", Swarm),
		write("service.create", "POST", "/services/create", Swarm),
		read("service.inspect", "GET", "/services/{id}", Swarm),
		write("service.delete", "DELETE", "/services/{id}", Swarm),
		write("service.update", "POST", "/services/{id}/update", Swarm),
		read("service.logs", "GET", "/services/{id}/logs", Swarm),
		read("task.list", "GET", "/tasks", Swarm),
		read("task.inspect", "GET", "/tasks/{id}", Swarm),
		read("task.logs", "GET", "/tasks/{id}/logs", Swarm),
		read("secret.list", "GET", "/secrets", Swarm),
		write("secret.create", "POST", "/secrets/create", Swarm),
		read("secret.inspect", "GET", "/secrets/{id}", Swarm),
		write("secret.delete", "DELETE", "/secrets/{id}", Swarm),
		write("secret.update", "POST", "/secrets/{id}/update", Swarm),
		read("config.list", "GET", "/configs", Swarm),
		write("config.create", "POST", "/configs/create", Swarm),
		read("config.inspect", "GET", "/configs/{id}", Swarm),
		write("config.delete", "DELETE", "/configs/{id}", Swarm),
		write("config.update", "POST", "/configs/{id}/update", Swarm),

		// Sessions: BuildKit's interactive sessions and gRPC tunnel
		upgrade(write("session.session", "POST", "/session", Session)),
		upgrade(write("session.grpc", "POST", "/grpc", Session)),
	}

	for i := range endpoints {
		endpoints[i].segments = strings.Split(strings.TrimPrefix(endpoints[i].Pattern, "/"), "/")
	}

	return endpoints
}()

// Endpoints lists the table, for documentation and tests.
func Endpoints() []Endpoint {
	return append([]Endpoint(nil), table...)
}
