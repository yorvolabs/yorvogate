package gate

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// A mount's volume options set labels on the volume Docker creates for it: they may not mark it as
// another scope's, and the volume gets the scope's owner label.
func TestAVolumeAMountCreatesIsItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	mount := func(source string, labels map[string]any) map[string]any {
		m := map[string]any{"Type": "volume", "Target": "/data", "Source": source}
		if labels != nil {
			m["VolumeOptions"] = map[string]any{"Labels": labels}
		}

		return set(compose(), "HostConfig.Mounts", []any{m})
	}

	for name, body := range map[string]map[string]any{
		"a named volume labelled as another scope's": mount("jane_planted", map[string]any{"com.docker.compose.project": "jane-blog"}),
		"an anonymous volume labelled as another's":  mount("", map[string]any{"com.docker.compose.project": "jane-blog"}),
		"another's label beside other labels":        mount("jane_planted", map[string]any{"x": "y", "com.docker.compose.project": "jane-blog"}),
	} {
		status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", encode(body), asJane)
		if status != http.StatusForbidden || !strings.Contains(message(t, answer), "its labels mark the volume as another scope's") {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}

	for name, c := range map[string]struct {
		body map[string]any
		want map[string]string
	}{
		"no labels":         {mount("jane_data", nil), map[string]string{"com.docker.compose.project": "jane"}},
		"labels of its own": {mount("jane_data", map[string]any{"x": "y"}), map[string]string{"x": "y", "com.docker.compose.project": "jane"}},
		"anonymous":         {mount("", nil), map[string]string{"com.docker.compose.project": "jane"}},
	} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", encode(c.body), asJane); status != 200 {
			t.Errorf("%s: %d %s", name, status, answer)

			continue
		}

		var forwarded container.CreateRequest
		if err := json.Unmarshal([]byte(d.last().body), &forwarded); err != nil {
			t.Fatal(err)
		}

		if got := forwarded.HostConfig.Mounts[0].VolumeOptions.Labels; !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: the volume's labels %v, want %v", name, got, c.want)
		}
	}
}

// Networks and volumes a scope creates carry its owner label, and no other scope's.
func TestWhatItCreatesIsLabelledItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for name, c := range map[string][2]string{
		"a volume, another's label":  {"/v1.56/volumes/create", `{"Name":"jane_x","Labels":{"com.docker.compose.project":"jane-blog"}}`},
		"a network, another's label": {"/v1.56/networks/create", encode(set(composeNetwork(), "Labels", map[string]any{"com.docker.compose.project": "jane-blog"}))},
	} {
		if status, answer := send(t, server, "POST", c[0], c[1], asJane); status != http.StatusForbidden || !strings.Contains(message(t, answer), "another scope's") {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}
}

// Every field of the request types that sets labels on an object Docker creates is one YorvoGate
// checks. A new one (a newer API) fails this test until it's checked and listed here.
func TestEveryLabelFieldIsChecked(t *testing.T) {
	checked := map[string][]string{
		// Labels (Config's, embedded at the body's top level): ownLabels. Mounts' VolumeOptions.Labels:
		// mount, and the owner label added.
		"container.create": {"Labels", "HostConfig.Mounts[].VolumeOptions.Labels"},
		"network.create":   {"Labels"},
		"volume.create":    {"Labels"},
	}

	for endpoint, typ := range map[string]reflect.Type{
		"container.create": reflect.TypeOf(container.CreateRequest{}),
		"network.create":   reflect.TypeOf(network.CreateRequest{}),
		"volume.create":    reflect.TypeOf(volume.CreateRequest{}),
	} {
		var found []string
		labelFields(typ, "", map[reflect.Type]bool{}, &found)
		slices.Sort(found)

		want := slices.Clone(checked[endpoint])
		slices.Sort(want)

		if !slices.Equal(found, want) {
			t.Errorf("%s: fields that set labels %v, checked %v", endpoint, found, want)
		}
	}
}

// labelFields lists the paths of a type's fields named Labels (or ending with it), through structs,
// pointers, slices and maps.
func labelFields(t reflect.Type, path string, seen map[reflect.Type]bool, found *[]string) {
	switch t.Kind() {
	case reflect.Pointer:
		labelFields(t.Elem(), path, seen, found)
	case reflect.Slice, reflect.Array:
		labelFields(t.Elem(), path+"[]", seen, found)
	case reflect.Map:
		labelFields(t.Elem(), path+"[]", seen, found)
	case reflect.Struct:
		if seen[t] {
			return
		}

		seen[t] = true
		defer delete(seen, t)

		for i := range t.NumField() {
			f := t.Field(i)
			// An embedded struct's fields are its parent's (as in JSON).
			name := path
			if !f.Anonymous {
				name = strings.TrimPrefix(path+"."+f.Name, ".")
			}

			if strings.HasSuffix(f.Name, "Labels") && f.Type.Kind() == reflect.Map {
				*found = append(*found, name)

				continue
			}

			labelFields(f.Type, name, seen, found)
		}
	}
}
