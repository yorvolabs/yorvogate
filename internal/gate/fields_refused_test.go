package gate

import (
	"encoding"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/moby/moby/api/types/network"
)

// fieldBase is a body a rule allows, for generating requests that set one field each: where it's
// sent, and, where a field holds one of several classifications, the map key (an endpoint's network)
// or the path (a connect's network) that makes it that one.
type fieldBase struct {
	of   *classification
	path string
	body string
	// For a field holding several classifications: the key of a map that makes each one
	keys map[*classification]string
	// Only this one of several classifications a field holds (the path chose it)
	only *classification
}

func fieldBases(t *testing.T) []fieldBase {
	create, err := json.Marshal(compose())
	if err != nil {
		t.Fatal(err)
	}

	network, err := json.Marshal(composeNetwork())
	if err != nil {
		t.Fatal(err)
	}

	return []fieldBase{
		{of: createRequest, path: "/v1.56/containers/create?name=jane-php-9", body: string(create),
			keys: map[*classification]string{endpointOwn: "jane_default", endpointShared: "quire-link-jane"}},
		{of: updateConfig, path: "/v1.56/containers/jane-php-1/update", body: `{"Memory":268435456}`},
		{of: execCreate, path: "/v1.56/containers/jane-php-1/exec", body: `{"Cmd":["true"]}`},
		{of: dialStdioCreate, path: "/v1.56/containers/buildx_buildkit_jane0/exec", body: dialStdioExec},
		{of: execStart, path: "/v1.56/exec/exec-jane/start", body: `{"Detach":true}`},
		{of: networkCreate, path: "/v1.56/networks/create", body: string(network)},
		{of: networkConnect, path: "/v1.56/networks/jane_default/connect", body: `{"Container":"jane-php-1"}`, only: endpointOwn},
		{of: networkConnect, path: "/v1.56/networks/quire-link-jane/connect", body: `{"Container":"jane-php-1"}`, only: endpointShared},
		{of: networkDisconnect, path: "/v1.56/networks/jane_default/disconnect", body: `{"Container":"jane-php-1"}`},
		{of: volumeCreate, path: "/v1.56/volumes/create", body: `{"Name":"jane_data","Driver":"local","Labels":{"com.docker.compose.project":"jane"}}`},
	}
}

// fieldTarget is one field reached from a base: the struct fields (and map keys) on the way to it.
type fieldTarget struct {
	steps []fieldStep
	in    *classification
	d     decision
	// reach: not a refused field, but a struct a checked or free field holds, given as its zero value
	// to see its classification applied
	reach bool
}

type fieldStep struct {
	f   reflect.StructField
	key string
}

func (x fieldTarget) String() string {
	var names []string
	for _, s := range x.steps {
		if !s.f.Anonymous {
			names = append(names, apiName(s.f))
		}
	}

	return strings.Join(names, ".")
}

// fieldTargets are every refused field at any depth of a base, and every struct its free and checked
// fields hold.
func fieldTargets(b fieldBase, c *classification, prefix []fieldStep) []fieldTarget {
	var out []fieldTarget

	for _, f := range exported(c.of) {
		d := c.fields[f.Name]
		steps := append(append([]fieldStep(nil), prefix...), fieldStep{f: f})

		if d.class == isRefused {
			out = append(out, fieldTarget{steps: steps, in: c, d: d})

			continue
		}

		for _, n := range d.nested {
			if len(d.nested) > 1 && b.only != nil && n != b.only {
				continue
			}

			s := append([]fieldStep(nil), steps...)
			s[len(s)-1].key = b.keys[n]

			if !f.Anonymous {
				out = append(out, fieldTarget{steps: s, in: n, reach: true})
			}

			out = append(out, fieldTargets(b, n, s)...)
		}
	}

	return out
}

// reach is the value a target's steps lead to, made where it's missing: a pointer's struct, a
// list's first element, a map's value at its key.
func reach(t *testing.T, v reflect.Value, steps []fieldStep) reflect.Value {
	for i, s := range steps {
		v = v.FieldByIndex(s.f.Index)
		if i == len(steps)-1 {
			return v
		}

		v = into(t, v, s.key)
	}

	return v
}

// into steps into what a field holds, making it if it's missing.
func into(t *testing.T, v reflect.Value, key string) reflect.Value {
	for {
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}

			v = v.Elem()
		case reflect.Slice:
			if v.Len() == 0 {
				v.Set(reflect.Append(v, reflect.Zero(v.Type().Elem())))
			}

			v = v.Index(0)
		case reflect.Map:
			if v.IsNil() {
				v.Set(reflect.MakeMap(v.Type()))
			}

			if v.Type().Elem().Kind() != reflect.Pointer {
				t.Fatalf("a map of %s on the way to a field: only maps of pointers are stepped into", v.Type().Elem())
			}

			k := reflect.ValueOf(key).Convert(v.Type().Key())
			e := v.MapIndex(k)

			if !e.IsValid() || e.IsNil() {
				e = reflect.New(v.Type().Elem().Elem())
				v.SetMapIndex(k, e)
			}

			v = e
		default:
			return v
		}
	}
}

// nonZero is a value of a type that asks for something.
func nonZero(t reflect.Type) reflect.Value {
	v := reflect.New(t).Elem()

	switch t {
	case reflect.TypeFor[netip.Addr]():
		v.Set(reflect.ValueOf(netip.MustParseAddr("10.213.0.99")))

		return v
	case reflect.TypeFor[netip.Prefix]():
		v.Set(reflect.ValueOf(netip.MustParsePrefix("10.213.0.96/27")))

		return v
	case reflect.TypeFor[network.HardwareAddr]():
		v.Set(reflect.ValueOf(network.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}))

		return v
	}

	switch t.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.String:
		v.SetString("x")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Pointer:
		v.Set(reflect.New(t.Elem()))
	case reflect.Slice:
		v.Set(reflect.Append(v, nonZero(t.Elem())))
	case reflect.Array:
		v.Index(0).Set(nonZero(t.Elem()))
	case reflect.Map:
		v.Set(reflect.MakeMap(t))
		v.SetMapIndex(mapKey(t.Key()), nonZero(t.Elem()))
	}

	return v
}

// mapKey is a key of a map's key type: parsed from text where the type parses itself (a port).
func mapKey(t reflect.Type) reflect.Value {
	k := reflect.New(t)
	if u, ok := k.Interface().(encoding.TextUnmarshaler); ok && u.UnmarshalText([]byte("80/tcp")) == nil {
		return k.Elem()
	}

	return reflect.ValueOf("x").Convert(t)
}

// Every refused field, at any depth of every body, is refused when a body sets it: the decision is
// applied by its rule, not only recorded (0.3-e, E1). And every classification a body's fields hold
// is applied where they're given, which a field refused nowhere yet (Ulimit's) would otherwise never
// show.
func TestEveryRefusedFieldIsRefused(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	var mu sync.Mutex

	var applied map[*classification]bool

	applying = func(c *classification) {
		mu.Lock()
		applied[c] = true
		mu.Unlock()
	}

	t.Cleanup(func() { applying = nil })

	refusals, classifications := 0, 0

	for _, b := range fieldBases(t) {
		// What this base's rule applies, apart from every other's (an update's ulimits aren't a
		// create's)
		mu.Lock()
		applied = map[*classification]bool{}
		mu.Unlock()

		reached := map[*classification]bool{b.of: true}

		if status, answer := send(t, server, "POST", b.path, b.body, asJane); status != 200 && status != 201 {
			t.Fatalf("%s: the base is refused: %d %s", b.path, status, answer)
		}

		for _, x := range fieldTargets(b, b.of, nil) {
			values := []reflect.Value{{}}
			if x.d.empty == emptyAsks {
				values = append(values, reflect.MakeSlice(x.steps[len(x.steps)-1].f.Type, 0, 0))
			}

			for _, value := range values {
				body := reflect.New(b.of.of)
				if err := json.Unmarshal([]byte(b.body), body.Interface()); err != nil {
					t.Fatal(err)
				}

				v := reach(t, body.Elem(), x.steps)

				switch {
				case x.reach:
					v.Set(reflect.Zero(v.Type()))
					into(t, v, x.steps[len(x.steps)-1].key)
				case value.IsValid():
					v.Set(value)
				default:
					v.Set(nonZero(v.Type()))
				}

				raw, err := json.Marshal(body.Interface())
				if err != nil {
					t.Fatal(err)
				}

				status, answer := send(t, server, "POST", b.path, string(raw), asJane)
				if x.reach {
					reached[x.in] = true

					continue
				}

				refusals++

				if name := apiName(x.steps[len(x.steps)-1].f); status/100 != 4 || !strings.Contains(strings.ToLower(message(t, answer)), strings.ToLower(name)) {
					t.Errorf("%s %s [%s] set: %d %s; want it refused, naming %s", b.path, x, x.in.name, status, answer, name)
				}
			}
		}

		mu.Lock()
		for c := range reached {
			classifications++

			if !applied[c] {
				t.Errorf("%s: %s given in its body, but its rule never applied its decisions", b.path, c.name)
			}
		}
		mu.Unlock()
	}

	t.Logf("%d refused fields set and refused; %d classifications given and applied, base by base", refusals, classifications)

	if refusals < 50 {
		t.Errorf("only %d refused fields set: the bodies weren't walked as expected", refusals)
	}

}
