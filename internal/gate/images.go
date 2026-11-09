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

// readsImage checks an image the scope reads (inspects, saves, tags from, runs): Docker is asked which
// image the name or ID is. The name it's read by may not be in another scope's protected namespace,
// and the image needs at least one name the scope may see: an image all of whose names are another
// scope's is that scope's (its layers hold its code, its configuration its environment), however it's
// referred to; one tagged both "alpine" and into a scope's namespace is still alpine for everyone. An
// image with no name at all (a build's leftover) may be anyone's: it isn't read. What's checked is
// returned: the caller names the image by it, so a name moved after the check changes nothing.
func (s *scoped) readsImage(ref string) (*image, error) {
	missing := refuse(http.StatusNotFound, "No such image: %s", ref)

	if s.image(ref) != nil {
		return nil, missing
	}

	img, err := s.docker.Image(s.ctx, s.version, ref)
	if err != nil {
		return nil, err
	}

	if img == nil {
		return nil, missing
	}

	// By name, ID or digest ("anything@sha256:…"): an image with no name the scope may see isn't read.
	if len(s.visible(img.Tags)) == 0 {
		return nil, missing
	}

	return img, nil
}

// pinned is how a container runs the image checked for it: by its ID, and on the containerd store by
// "name@ID" for the name it was asked by, which Docker resolves only while that name's repository
// still has the image (and which shows as the container's image). Everything in it is Docker's: the
// ID it answered, and the repository of one of the image's own names, never the client's text. An
// image asked by its ID, or by a name it doesn't have, is run by the ID alone.
func pinned(ref string, img *image) string {
	if !img.Containerd {
		return string(img.ID)
	}

	repo := repository(ref)
	for _, tag := range img.Tags {
		if r := repository(tag); imageName(r) == imageName(repo) {
			return r + "@" + string(img.ID)
		}
	}

	return string(img.ID)
}

// repository is a reference without its digest or tag: "host:5000/a/b:1@sha256:…" is "host:5000/a/b".
func repository(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}

	return ref
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

// pull checks a pull: from a registry by name, and not into another scope's protected namespace. An
// import (from a URL or an archive) is refused by its parameters (forScopes).
func (s *scoped) pull() error {
	// Docker reads an import's archive from the body; a pull has none.
	if s.hasBody {
		return refuse(http.StatusBadRequest, "image.create has no body: a pull's parameters are in its query")
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

// tag checks a tag: from an image it may read (the one checked, by its ID), into a name of its own.
func (s *scoped) tag() error {
	img, err := s.readsImage(s.req.Params["name"])
	if err != nil {
		return err
	}

	s.with("name", img.ID)

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

		if len(s.visible(tags)) == 0 {
			continue
		}

		if err := s.filterNames(img, "RepoTags", "RepoDigests"); err != nil {
			return nil, err
		}

		kept = append(kept, img)
	}

	return json.Marshal(kept)
}

// imageNames filters an image's inspection: its tags and digests name it only as the scope may see
// it. (YorvoGate inspects only an image with at least one such name.)
func (s *scoped) imageNames(body []byte) ([]byte, error) {
	var img map[string]json.RawMessage
	if err := json.Unmarshal(body, &img); err != nil {
		return nil, err
	}

	if err := s.filterNames(img, "RepoTags", "RepoDigests"); err != nil {
		return nil, err
	}

	return json.Marshal(img)
}

// history filters an image's history: each layer's image is named only as the scope may see it.
func (s *scoped) history(body []byte) ([]byte, error) {
	var layers []map[string]json.RawMessage
	if err := json.Unmarshal(body, &layers); err != nil {
		return nil, err
	}

	for _, layer := range layers {
		if err := s.filterNames(layer, "Tags"); err != nil {
			return nil, err
		}
	}

	return json.Marshal(layers)
}

// filterNames keeps, in each of an answer's fields that list image names ("name:tag" or
// "name@digest"), only the names the scope may see. A field that isn't there stays absent, and a null
// stays null.
func (s *scoped) filterNames(object map[string]json.RawMessage, fields ...string) error {
	for _, field := range fields {
		raw, ok := object[field]
		if !ok || string(raw) == "null" {
			continue
		}

		var names []string
		if err := json.Unmarshal(raw, &names); err != nil {
			return fmt.Errorf("%s isn't a list of names: %w", field, err)
		}

		seen := s.visible(names)
		if seen == nil {
			seen = []string{}
		}

		object[field], _ = json.Marshal(seen)
	}

	return nil
}
