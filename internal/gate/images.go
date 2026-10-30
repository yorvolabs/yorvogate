package gate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var imageID = regexp.MustCompile(`^(sha256:)?[0-9a-f]{12,64}$`)

// imageName is an image's name as YorvoGate compares it: without Docker Hub's registry and library
// namespace, which Docker adds to a short name ("alpine" is "docker.io/library/alpine").
func imageName(ref string) string {
	for _, prefix := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		ref = strings.TrimPrefix(ref, prefix)
	}

	return strings.TrimPrefix(ref, "library/")
}

// image checks an image's name: never in a protected namespace that isn't the scope's own.
func (s *scoped) image(image string) error {
	name := imageName(image)

	for _, p := range s.policy.ProtectedImages {
		if strings.HasPrefix(name, p) && !s.scope.OwnsImage(name) {
			return fmt.Errorf("the image %s is in a protected namespace (%s) that isn't its own", image, p)
		}
	}

	return nil
}

// readsImage checks an image the scope reads (inspects, saves, tags from): Docker is asked which
// image the name or ID is. The name it's read by may not be in another scope's protected namespace,
// and the image needs at least one name the scope may see: an image all of whose names are another
// scope's is that scope's (its layers hold its code, its configuration its environment), however it's
// referred to; one tagged both "alpine" and into a scope's namespace is still alpine for everyone. An
// image with no name at all (a build's leftover) may be anyone's: it isn't read.
func (s *scoped) readsImage(ref string) error {
	missing := refuse(http.StatusNotFound, "No such image: %s", ref)

	if s.image(ref) != nil {
		return missing
	}

	img, err := s.docker.Image(s.ctx, s.version, ref)
	if err != nil {
		return err
	}

	if img == nil {
		return missing
	}

	// By name, ID or digest ("anything@sha256:…"): an image with no name the scope may see isn't read.
	if len(s.visible(img.Tags)) == 0 {
		return missing
	}

	return nil
}

// visible are the names of an image the scope may see: not in another scope's protected namespace.
func (s *scoped) visible(tags []string) []string {
	var seen []string

	for _, tag := range tags {
		if s.image(tag) == nil {
			seen = append(seen, tag)
		}
	}

	return seen
}

// ownsImageName checks a name a scope writes (tags, loads, deletes): in one of its own namespaces
// only. Any other name may be another's to run: retagging "postgres:18" would change what every
// container that names it runs next.
func (s *scoped) ownsImageName(ref, what string) error {
	if imageID.MatchString(ref) || !s.scope.OwnsImage(imageName(ref)) {
		return refuse(http.StatusForbidden, "%s: %s isn't in one of scope %s's image namespaces (%s)", what, ref, s.scope.Name, list(s.scope.Images))
	}

	return nil
}

// pull checks a pull: from a registry by name (never an import from a URL or an archive), and not
// into another scope's protected namespace.
func (s *scoped) pull() error {
	if s.query.Get("fromSrc") != "" {
		return refuse(http.StatusForbidden, "image.create: importing (fromSrc) isn't allowed, only pulls")
	}

	from := s.query.Get("fromImage")
	if from == "" {
		return refuse(http.StatusBadRequest, "image.create: fromImage is missing")
	}

	ref := from
	if tag := s.query.Get("tag"); tag != "" {
		if strings.HasPrefix(tag, "sha256:") {
			ref += "@" + tag
		} else {
			ref += ":" + tag
		}
	}

	if err := s.image(ref); err != nil {
		return refuse(http.StatusForbidden, "image.create: %v", err)
	}

	return nil
}

// tag checks a tag: from an image it may read, into a name of its own.
func (s *scoped) tag() error {
	if err := s.readsImage(s.req.Params["name"]); err != nil {
		return err
	}

	target := s.query.Get("repo")
	if tag := s.query.Get("tag"); tag != "" {
		target += ":" + tag
	}

	return s.ownsImageName(target, "image.tag")
}

// images filters an image list's answer: an image is listed with the names the scope may see, and not
// at all when it has none (another scope's, or a nameless leftover).
func (s *scoped) images(body []byte) ([]byte, error) {
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}

	kept := make([]map[string]json.RawMessage, 0, len(list))

	for _, img := range list {
		var tags []string
		_ = json.Unmarshal(img["RepoTags"], &tags)

		if seen := s.visible(tags); len(seen) > 0 {
			img["RepoTags"], _ = json.Marshal(seen)
			kept = append(kept, img)
		}
	}

	return json.Marshal(kept)
}
