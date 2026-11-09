package gate

import "strings"

// The two rules on what a container may mount from a volume, used wherever one is mounted, created
// or found in a builder: one copy each, so a rule tightened here holds everywhere.

// hostPath tells whether a bind's or a mount's source names a host path (or nothing), not a volume.
func hostPath(source string) bool {
	return source == "" || strings.ContainsAny(source, "/\\") || strings.HasPrefix(source, ".") || strings.HasPrefix(source, "~")
}

// plainLocal tells whether a volume's driver and options keep it in Docker's own storage. A local
// volume with options can bind a host path (type=none,o=bind,device=/); any other driver is a plugin
// on the host, which could do anything.
func plainLocal(driver string, options map[string]string) bool {
	return (driver == "" || driver == "local") && len(options) == 0
}
