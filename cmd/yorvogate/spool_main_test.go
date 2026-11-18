package main

import (
	"os"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// The tests' configurations have no state file: their spool's folder is a temporary one, not
// /var/lib/yorvogate/spool, which check would rightly refuse where it can't be written.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "yorvogate-spool-")
	if err != nil {
		panic(err)
	}

	config.DefaultSpoolDir = dir
	code := m.Run()

	_ = os.RemoveAll(dir)
	os.Exit(code)
}
