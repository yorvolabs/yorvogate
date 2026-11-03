package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// NewServer serves a listener's requests, with the limits every listener has.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}

// bodyReadTimeout bounds how long YorvoGate waits for a non-stream request body (a small JSON value
// it checks): long enough for a slow link, short enough that a trickled body can't hold a connection
// open indefinitely.
var bodyReadTimeout = 30 * time.Second

// maxConnections is how many connections one listener accepts at once. For a scope-bound socket it's
// per scope (each scope has its own socket), so one scope can't take the file descriptors the others
// need; for a shared address it bounds the whole listener. Generous for a tenant's real use.
const MaxConnections = 256

// LimitListener accepts at most n connections at once; past that, Accept waits for one to close. It
// bounds the file descriptors a listener (and, for a scope socket, a scope) can tie up.
func LimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n)}
}

type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}

	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem

		return nil, err
	}

	return &limitConn{Conn: conn, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)

	return err
}

// umask is the process's: it's set only while a socket is made.
var umask sync.Mutex

// Listen makes a unix socket that only its owner and group may connect to (0660). It's made under a
// umask that leaves it its owner's only until its group and mode are set, so no one else can
// connect in between. A stale socket at the path is replaced; any other file is left, and is an
// error.
func Listen(path string, gid int) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}

	umask.Lock()
	old := syscall.Umask(0o177)
	listener, err := net.Listen("unix", path)
	syscall.Umask(old)
	umask.Unlock()

	if err != nil {
		return nil, err
	}

	if gid >= 0 {
		if err := os.Lchown(path, -1, gid); err != nil {
			_ = listener.Close()

			return nil, err
		}
	}

	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()

		return nil, err
	}

	return LimitListener(listener, MaxConnections), nil
}

// Group is the ID of a listener's socket_group, or -1 when it has none (the process's own).
func Group(l config.Listener) (int, error) {
	if l.SocketGroup == "" {
		return -1, nil
	}

	id := l.SocketGroup
	if _, err := strconv.Atoi(id); err != nil {
		g, err := user.LookupGroup(l.SocketGroup)
		if err != nil {
			return 0, fmt.Errorf("socket_group: %w", err)
		}

		id = g.Gid
	}

	return strconv.Atoi(id)
}

// Sockets are a socket-bound listener's: one socket per valid scope, "<scope>.sock" in its folder.
// A request on a socket is that scope's. Scan makes the sockets of new scopes, and closes those of
// scopes removed or no longer valid, connections and streams included.
type Sockets struct {
	gate *Gate
	dir  string
	gid  int
	log  *slog.Logger

	mu   sync.Mutex
	open map[string]*boundSocket
	// Why each scope file that isn't valid isn't, as last logged
	reported map[string]string
	stopped  bool
	// Serve's errors (a socket that stopped accepting)
	failed chan error
}

type boundSocket struct {
	server   *http.Server
	listener *tracked
}

// NewSockets prepares a socket-bound listener's sockets; Scan makes them.
func NewSockets(g *Gate, log *slog.Logger) (*Sockets, error) {
	l := g.listener
	if !l.SocketBound() {
		return nil, fmt.Errorf("listener %s has no scope_sockets", l.Name)
	}

	info, err := os.Stat(l.ScopeSockets)
	if err != nil {
		return nil, fmt.Errorf("scope_sockets: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("scope_sockets: %s isn't a folder", l.ScopeSockets)
	}

	gid, err := Group(l)
	if err != nil {
		return nil, err
	}

	return &Sockets{
		gate: g, dir: l.ScopeSockets, gid: gid, log: log.With("listener", l.Name),
		open: map[string]*boundSocket{}, reported: map[string]string{}, failed: make(chan error, 1),
	}, nil
}

// Failed gives an error when a socket stops accepting connections for any reason but being closed.
func (s *Sockets) Failed() <-chan error {
	return s.failed
}

// Scan brings the sockets in line with the scope folder: a socket for each valid scope, none for
// any other.
func (s *Sockets) Scan() error {
	names, invalid, err := s.gate.scopes.Scopes()
	if err != nil {
		return err
	}

	valid := make(map[string]bool, len(names))
	for _, name := range names {
		valid[name] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return nil
	}

	for name, socket := range s.open {
		if valid[name] {
			continue
		}

		socket.close()
		delete(s.open, name)

		if err, ok := invalid[name]; ok {
			s.log.Warn("socket closed: its scope isn't valid", "scope", name, "reason", err.Error())
		} else {
			s.log.Info("socket closed: its scope was removed", "scope", name)
		}
	}

	var failed []error

	for _, name := range names {
		if _, ok := s.open[name]; ok {
			continue
		}

		if err := s.serve(name); err != nil {
			// Tried again at the next scan
			failed = append(failed, fmt.Errorf("scope %s's socket: %w", name, err))
		}
	}

	for name, err := range invalid {
		if s.reported[name] != err.Error() {
			s.log.Warn("scope file isn't valid", "scope", name, "reason", err.Error())
			s.reported[name] = err.Error()
		}
	}

	for name := range s.reported {
		if _, ok := invalid[name]; !ok {
			delete(s.reported, name)
		}
	}

	return errors.Join(failed...)
}

// serve opens a scope's socket.
func (s *Sockets) serve(name string) error {
	path := filepath.Join(s.dir, name+".sock")

	listener, err := Listen(path, s.gid)
	if err != nil {
		return err
	}

	t := &tracked{Listener: listener, conns: map[*trackedConn]struct{}{}}
	server := NewServer(s.gate)
	server.BaseContext = func(net.Listener) context.Context {
		return context.WithValue(context.Background(), boundKey{}, name)
	}

	s.open[name] = &boundSocket{server: server, listener: t}

	go func() {
		if err := server.Serve(t); !errors.Is(err, http.ErrServerClosed) && !t.isClosed() {
			select {
			case s.failed <- fmt.Errorf("scope %s's socket: %w", name, err):
			default:
			}
		}
	}()

	s.log.Info("socket opened", "scope", name, "socket", path)

	return nil
}

// Shutdown closes every socket: requests that are being answered may finish until the context
// ends; streams are closed then.
func (s *Sockets) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.stopped = true
	open := s.open
	s.open = map[string]*boundSocket{}
	s.mu.Unlock()

	var wg sync.WaitGroup

	for _, socket := range open {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_ = socket.server.Shutdown(ctx)
			socket.close()
		}()
	}

	wg.Wait()
}

// close stops a socket at once: its file goes, and every connection on it (streams included) is
// closed.
func (b *boundSocket) close() {
	_ = b.server.Close()
	b.listener.closeAll()
}

// tracked is a listener that knows its connections, including those an upgrade took from the HTTP
// server (attach, exec, BuildKit's dial-stdio), so closing a socket closes them too.
type tracked struct {
	net.Listener

	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	closed bool
}

func (t *tracked) Accept() (net.Conn, error) {
	c, err := t.Listener.Accept()
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		_ = c.Close()

		return nil, net.ErrClosed
	}

	tc := &trackedConn{Conn: c, listener: t}
	t.conns[tc] = struct{}{}

	return tc, nil
}

func (t *tracked) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.closed
}

func (t *tracked) closeAll() {
	t.mu.Lock()
	t.closed = true
	conns := t.conns
	t.conns = map[*trackedConn]struct{}{}
	t.mu.Unlock()

	_ = t.Listener.Close()

	for c := range conns {
		_ = c.Conn.Close()
	}
}

type trackedConn struct {
	net.Conn

	listener *tracked
	once     sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()

	c.once.Do(func() {
		c.listener.mu.Lock()
		delete(c.listener.conns, c)
		c.listener.mu.Unlock()
	})

	return err
}
