package gate

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var logSchema = func() *jsonschema.Schema {
	s, err := jsonschema.NewCompiler().Compile("../../schemas/yorvogate-log.v1.schema.json")
	if err != nil {
		panic(err)
	}

	return s
}()

// logChecker takes a gate's log lines in a test: each must be the log schema's, and none may hold a
// token (a secret is never logged, whatever the line).
type logChecker struct {
	t     testing.TB
	mu    sync.Mutex
	buf   []byte
	done  bool
	lines []string
	// Told of each line (a test waits on it)
	more chan struct{}
}

func (c *logChecker) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.buf = append(c.buf, p...)

	for {
		i := bytes.IndexByte(c.buf, '\n')
		if i < 0 {
			break
		}

		line := string(c.buf[:i])
		c.buf = c.buf[i+1:]
		c.lines = append(c.lines, line)

		select {
		case c.more <- struct{}{}:
		default:
		}

		if c.done {
			continue
		}

		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err == nil {
			err = logSchema.Validate(doc)
		}

		if err != nil {
			c.t.Errorf("a log line isn't the schema's: %v\n%s", err, line)
		}

		for _, secret := range []string{token, blogToken} {
			if strings.Contains(line, secret) {
				c.t.Errorf("a log line holds a token: %s", line)
			}
		}
	}

	return len(p), nil
}

// Lines are what was logged so far.
func (c *logChecker) Lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string(nil), c.lines...)
}

// checkedLog is a logger whose every line is checked, for the test's whole run.
func checkedLog(t testing.TB) (*slog.Logger, *logChecker) {
	c := &logChecker{t: t, more: make(chan struct{}, 1)}
	t.Cleanup(func() { c.mu.Lock(); c.done = true; c.mu.Unlock() })

	return slog.New(slog.NewJSONHandler(c, &slog.HandlerOptions{Level: slog.LevelDebug})), c
}

// waitFor is the first line (decoded) that matches, waiting for it up to 5 s.
func (c *logChecker) waitFor(t *testing.T, match func(map[string]any) bool) map[string]any {
	t.Helper()
	timeout := time.After(5 * time.Second)

	for {
		for _, l := range c.Lines() {
			var line map[string]any
			if json.Unmarshal([]byte(l), &line) == nil && match(line) {
				return line
			}
		}

		select {
		case <-c.more:
		case <-timeout:
			t.Fatal("no such log line in 5 s")

			return nil
		}
	}
}
