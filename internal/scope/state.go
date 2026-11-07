package scope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// stateVersion is the state file's format.
const stateVersion = 1

// state is the state file: each scope's last accepted claims. It only ever keeps claims out of
// other scopes' reach. A scope acts on its own file alone, so a stale or edited state file can
// refuse names (it can deny service) but never gives any scope a name, label or image its own file
// doesn't claim.
type state struct {
	Version int               `json:"version"`
	Scopes  map[string]claims `json:"scopes"`
}

// readState reads the held claims. No file is no claims; a file that can't be trusted is no
// claims too, and the error says why.
func readState(path string) (map[string]claims, error) {
	held := map[string]claims{}
	if path == "" {
		return held, nil
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return held, nil
	} else if err != nil {
		return held, fmt.Errorf("state file %s: %w", path, err)
	}

	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return held, fmt.Errorf("state file %s: must be a plain file, writable by its owner only; nothing it holds is kept", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return held, fmt.Errorf("state file %s: %w", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var s state
	if err := decoder.Decode(&s); err != nil {
		return held, fmt.Errorf("state file %s: %w; nothing it holds is kept", path, err)
	}

	if s.Version != stateVersion {
		return held, fmt.Errorf("state file %s: version %d isn't one this build reads (%d); nothing it holds is kept", path, s.Version, stateVersion)
	}

	var bad []string

	for name, c := range s.Scopes {
		if !validName.MatchString(name) || !c.valid() {
			bad = append(bad, name)

			continue
		}

		held[name] = c
	}

	if len(bad) > 0 {
		sort.Strings(bad)

		return held, fmt.Errorf("state file %s: records not valid, not kept: %q", path, bad)
	}

	return held, nil
}

func (c claims) valid() bool {
	if !validLabel.MatchString(c.Owner.Key) || !validValue.MatchString(c.Owner.Value) || len(c.Prefixes) == 0 {
		return false
	}

	for _, p := range c.Prefixes {
		if !validPrefix.MatchString(p) {
			return false
		}
	}

	for _, i := range c.Images {
		if !validImage.MatchString(i) {
			return false
		}
	}

	for _, b := range c.Builders {
		if !validObject.MatchString(b) {
			return false
		}
	}

	return true
}

// writeState replaces the state file at once (a new file renamed over it), readable by its owner
// only.
func writeState(path string, held map[string]claims) error {
	content, err := json.MarshalIndent(state{Version: stateVersion, Scopes: held}, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".yorvogate-state-*")
	if err != nil {
		return fmt.Errorf("state file %s: %w", path, err)
	}

	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("state file %s: %w", path, err)
	}

	if _, err := tmp.Write(append(content, '\n')); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("state file %s: %w", path, err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("state file %s: %w", path, err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state file %s: %w", path, err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("state file %s: %w", path, err)
	}

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return nil
}
