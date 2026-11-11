package gate

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// pki is a CA for tests: it issues certificates on the fly.
type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var serial int64

func newCA(t testing.TB, name string) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := x509.ParseCertificate(der)

	return &pki{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf is what a certificate the CA issues says.
type leaf struct {
	names     []pkix.AttributeTypeAndValue // the subject, as written (a common name each)
	eku       []x509.ExtKeyUsage
	notBefore time.Time
	notAfter  time.Time
	server    bool
}

func client(names ...string) leaf {
	l := leaf{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for _, n := range names {
		l.names = append(l.names, pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: n})
	}

	return l
}

// issue makes a certificate and its key: the tls.Certificate, and the PEM of each.
func (p *pki) issue(t testing.TB, l leaf) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++

	if l.notBefore.IsZero() {
		l.notBefore = time.Now().Add(-time.Hour)
	}

	if l.notAfter.IsZero() {
		l.notAfter = time.Now().Add(12 * time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{ExtraNames: l.names},
		NotBefore: l.notBefore, NotAfter: l.notAfter, ExtKeyUsage: l.eku, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if l.server {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	return pair, certPEM, keyPEM
}

func pin(c tls.Certificate) string {
	key := SPKI(c.Leaf)

	return hex.EncodeToString(key[:])
}

// mtls is an mTLS gate: a scoped listener (scopes jane and blog, its clients' CA) and a trusted
// one (another CA), each served on its own address, in front of the fake Docker.
type mtls struct {
	server, clients, admins *pki
	dir, scopes             string
	set                     *TLS
	gate                    *Gate   // the scoped listener's
	gates                   []*Gate // both
	sites, trusted          string  // addresses
	log                     *bytes.Buffer
}

func mtlsGate(t *testing.T, d *docker, trustedClients string) *mtls {
	t.Helper()
	m := &mtls{server: newCA(t, "server CA"), clients: newCA(t, "scopes CA"), admins: newCA(t, "admins CA"), dir: t.TempDir(), scopes: t.TempDir(), log: &bytes.Buffer{}}
	writeScope(t, m.scopes, "jane", `{"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"]}`)
	writeScope(t, m.scopes, "blog", `{"owner": {"label": "com.docker.compose.project", "value": "blog"}, "prefixes": ["blog-", "blog_"]}`)

	pair := leaf{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, server: true}
	_, certPEM, keyPEM := m.server.issue(t, pair)
	m.write(t, "server.pem", certPEM)
	m.write(t, "server.key", keyPEM)
	m.write(t, "clients.pem", m.clients.pem)
	m.write(t, "admins.pem", m.admins.pem)

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + `
listeners:
  - name: sites
    address: tcp://0.0.0.0:2376
    mode: scoped
    scopes: ` + m.scopes + `
    tls: {certificate: ` + m.dir + `/server.pem, key: ` + m.dir + `/server.key, client_ca: ` + m.dir + `/clients.pem}
  - name: admin
    address: tcp://0.0.0.0:2375
    mode: trusted
    allow: {system: read, exec: write}
    tls: {certificate: ` + m.dir + `/server.pem, key: ` + m.dir + `/server.key, client_ca: ` + m.dir + `/admins.pem}
` + trustedClients))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(m.log, nil))
	if m.set, err = LoadTLS(c, log); err != nil {
		t.Fatal(err)
	}

	defaults := readDefaults(c)

	for i, l := range c.Listeners {
		g := New(c, l, NewUpstream(c, log), registry, defaults, log)
		g.UseTLS(m.set.For(l.Name))
		m.gates = append(m.gates, g)

		if i == 0 {
			m.gate = g
		}

		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		server := NewServer(g)
		go func() { _ = server.Serve(tls.NewListener(raw, m.set.For(l.Name).Config())) }()
		t.Cleanup(func() { _ = server.Close() })

		if i == 0 {
			m.sites = raw.Addr().String()
		} else {
			m.trusted = raw.Addr().String()
		}
	}

	return m
}

func (m *mtls) write(t *testing.T, name string, content []byte) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(m.dir, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// tlsConfig is a client's: the gate's server CA, and its certificate (none when nil).
func (m *mtls) tlsConfig(cert *tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(m.server.cert)
	c := &tls.Config{RootCAs: roots}

	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}

	return c
}

// get sends a request over TLS with a client certificate: its status and YorvoGate's message, or the
// error that stopped it.
func (m *mtls) get(t *testing.T, address string, cert *tls.Certificate, path string, header map[string]string) (int, string, error) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: m.tlsConfig(cert)}, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "https://"+address+path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}

	res, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = res.Body.Close() }()

	body, _ := io.ReadAll(res.Body)

	var answer struct{ Message string }
	_ = json.Unmarshal(body, &answer)

	return res.StatusCode, answer.Message, nil
}

// On an mTLS listener a client certificate is its scope: its one common name, exactly a scope's
// name. It's the only credential: a token is refused, not looked at.
func TestAClientCertificateIsItsScope(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	jane, _, _ := m.clients.issue(t, client("jane"))
	blog, _, _ := m.clients.issue(t, client("blog"))

	if status, msg, err := m.get(t, m.sites, &jane, "/v1.56/exec/exec-jane/json", nil); err != nil || status != 200 {
		t.Errorf("jane's exec, as jane: %d %s %v", status, msg, err)
	}

	if status, msg, _ := m.get(t, m.sites, &blog, "/v1.56/exec/exec-jane/json", nil); status != http.StatusNotFound {
		t.Errorf("jane's exec, as blog: %d %s", status, msg)
	}

	for _, c := range []struct {
		name   string
		cert   leaf
		header map[string]string
		status int
		want   string
	}{
		{"naming another scope", client("jane"), map[string]string{ScopeHeader: "blog"}, http.StatusForbidden, "this client certificate is scope jane's: a request with it can't name another"},
		{"naming its own", client("jane"), map[string]string{ScopeHeader: "jane"}, 200, ""},
		{"with a token", client("jane"), map[string]string{TokenHeader: token}, http.StatusBadRequest, "this listener takes a client certificate, not a token"},
		{"with jane's token, as blog", client("blog"), map[string]string{ScopeHeader: "jane", TokenHeader: token}, http.StatusBadRequest, "not a token"},
		{"a scope that isn't there", client("nobody"), nil, http.StatusUnauthorized, "no such scope, or not its certificate"},
		{"two common names", client("blog", "jane"), nil, http.StatusUnauthorized, "its subject has 2 common names"},
		{"no common name", client(), nil, http.StatusUnauthorized, "its subject has 0 common names"},
		{"a name that isn't a scope's", client("Jane"), nil, http.StatusUnauthorized, `its common name "Jane" isn't a scope's name`},
		{"a name with more", client("jane/blog"), nil, http.StatusUnauthorized, "isn't a scope's name"},
	} {
		cert, _, _ := m.clients.issue(t, c.cert)
		status, msg, err := m.get(t, m.sites, &cert, "/v1.56/exec/exec-jane/json", c.header)

		if err != nil || status != c.status || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %q %v", c.name, status, msg, err)
		}
	}
}

// A client certificate is taken only from the listener's CA, valid now, for client authentication,
// over TLS 1.3; anything else ends at the handshake.
func TestTheHandshakeRefusesOtherCertificates(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	other := newCA(t, "another CA")

	for name, cert := range map[string]func() tls.Certificate{
		"another CA's":    func() tls.Certificate { c, _, _ := other.issue(t, client("jane")); return c },
		"the admins CA's": func() tls.Certificate { c, _, _ := m.admins.issue(t, client("jane")); return c },
		"expired": func() tls.Certificate {
			c, _, _ := m.clients.issue(t, leaf{names: client("jane").names, eku: client().eku, notBefore: time.Now().Add(-2 * time.Hour), notAfter: time.Now().Add(-time.Hour)})
			return c
		},
		"not yet valid": func() tls.Certificate {
			c, _, _ := m.clients.issue(t, leaf{names: client("jane").names, eku: client().eku, notBefore: time.Now().Add(time.Hour), notAfter: time.Now().Add(2 * time.Hour)})
			return c
		},
		"a server's": func() tls.Certificate {
			c, _, _ := m.clients.issue(t, leaf{names: client("jane").names, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return c
		},
		"for no usage in particular": func() tls.Certificate {
			c, _, _ := m.clients.issue(t, leaf{names: client("jane").names})
			return c
		},
	} {
		c := cert()
		if status, msg, err := m.get(t, m.sites, &c, "/_ping", nil); err == nil {
			t.Errorf("%s: %d %s", name, status, msg)
		}
	}

	if status, msg, err := m.get(t, m.sites, nil, "/_ping", nil); err == nil {
		t.Errorf("no certificate: %d %s", status, msg)
	}

	// TLS 1.2 isn't spoken, with a valid certificate or not
	jane, _, _ := m.clients.issue(t, client("jane"))
	old := m.tlsConfig(&jane)
	old.MaxVersion = tls.VersionTLS12

	if conn, err := tls.Dial("tcp", m.sites, old); err == nil {
		_ = conn.Close()
		t.Error("a TLS 1.2 handshake")
	}

	if status, _, err := m.get(t, m.sites, &jane, "/_ping", nil); err != nil || status != 200 {
		t.Errorf("jane: %d %v", status, err)
	}
}

// A scope that pins its certificates' keys is only those: another certificate from the CA with its
// name isn't it.
func TestAScopesPinnedCertificates(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	first, _, _ := m.clients.issue(t, client("jane"))
	second, _, _ := m.clients.issue(t, client("jane"))
	scope := `{"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"], "certificates": [%s]}`

	writeScope(t, m.scopes, "jane", strings.Replace(scope, "%s", `{"sha256": "`+pin(first)+`"}`, 1))
	revoke(t, m.gate)

	if status, _, err := m.get(t, m.sites, &first, "/_ping", nil); err != nil || status != 200 {
		t.Errorf("the pinned one: %d %v", status, err)
	}

	if status, msg, _ := m.get(t, m.sites, &second, "/_ping", nil); status != http.StatusUnauthorized || !strings.HasSuffix(msg, ": no such scope, or not its certificate") {
		t.Errorf("another: %d %s", status, msg)
	}

	// A rotation: both pinned
	writeScope(t, m.scopes, "jane", strings.Replace(scope, "%s", `{"sha256": "`+pin(first)+`"}, {"sha256": "`+pin(second)+`"}`, 1))
	revoke(t, m.gate)

	for _, c := range []tls.Certificate{first, second} {
		if status, _, err := m.get(t, m.sites, &c, "/_ping", nil); err != nil || status != 200 {
			t.Errorf("during the rotation: %d %v", status, err)
		}
	}
}

// tlsStream starts an exec's stream over TLS with a client certificate.
func (m *mtls) tlsStream(t *testing.T, address, exec string, cert tls.Certificate) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := tls.Dial("tcp", address, m.tlsConfig(&cert))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	_, _ = conn.Write([]byte("POST /v1.56/exec/" + exec + "/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 16\r\n\r\n{\"Detach\":false}"))
	reader := bufio.NewReader(conn)

	res, err := http.ReadResponse(reader, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", res, err)
	}

	echoes(t, conn, reader)

	return conn, reader
}

// A certificate's streams end when its scope stops pinning it, or when it expires; another scope's
// go on.
func TestACertificatesStreamsEndWithIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(m *mtls, jane tls.Certificate)
	}{
		{"no longer pinned", func(m *mtls, jane tls.Certificate) {
			writeScope(t, m.scopes, "jane", `{"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"], "certificates": [{"sha256": "`+strings.Repeat("a", 64)+`"}]}`)
		}},
		{"expired", func(m *mtls, jane tls.Certificate) {
			expires := jane.Leaf.NotAfter
			clock = func() time.Time { return expires.Add(time.Second) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { clock = time.Now })
			d := startDocker(t)
			m := mtlsGate(t, d, "")
			jane, _, _ := m.clients.issue(t, client("jane"))
			blog, _, _ := m.clients.issue(t, leaf{names: client("blog").names, eku: client().eku, notAfter: time.Now().Add(48 * time.Hour)})

			writeScope(t, m.scopes, "jane", `{"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"], "certificates": [{"sha256": "`+pin(jane)+`"}]}`)
			revoke(t, m.gate)

			janeConn, janeReader := m.tlsStream(t, m.sites, "exec-jane", jane)
			blogConn, blogReader := m.tlsStream(t, m.sites, "exec-blog", blog)

			revoke(t, m.gate)
			echoes(t, janeConn, janeReader)

			tc.change(m, jane)
			revoke(t, m.gate)

			if !ended(t, janeConn, janeReader) {
				t.Error("jane's stream is still open")
			}

			echoes(t, blogConn, blogReader)
		})
	}
}

// A trusted listener's clients are its CA's certificates, or only those it pins.
func TestATrustedListenersClients(t *testing.T) {
	d := startDocker(t)
	other, _, _ := newCA(t, "unused").issue(t, client("x")) // a key for a pin no client has
	m := mtlsGate(t, d, "")
	admin, _, _ := m.admins.issue(t, client("anyone"))

	if status, _, err := m.get(t, m.trusted, &admin, "/_ping", nil); err != nil || status != 200 {
		t.Errorf("the admins CA's: %d %v", status, err)
	}

	jane, _, _ := m.clients.issue(t, client("jane"))
	if _, _, err := m.get(t, m.trusted, &jane, "/_ping", nil); err == nil {
		t.Error("a scope's certificate opened the trusted listener")
	}

	pinned := mtlsGate(t, d, "    clients: [{sha256: "+pin(other)+"}]\n")
	unpinned, _, _ := pinned.admins.issue(t, client("anyone"))

	if _, _, err := pinned.get(t, pinned.trusted, &unpinned, "/_ping", nil); err == nil {
		t.Error("a certificate the trusted listener doesn't pin")
	}
}

// What's pinned works on the trusted listener (its own test: the pin must be known before its
// configuration is written).
func TestATrustedListenersPinnedClient(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	admin, _, _ := m.admins.issue(t, client("anyone"))

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n  - name: admin\n    address: tcp://0.0.0.0:2375\n    mode: trusted\n    allow: {system: read}\n    tls: {certificate: " + m.dir + "/server.pem, key: " + m.dir + "/server.key, client_ca: " + m.dir + "/admins.pem}\n    clients: [{sha256: " + pin(admin) + "}]\n"))
	if err != nil {
		t.Fatal(err)
	}

	set, err := LoadTLS(c, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	log := slog.New(slog.DiscardHandler)
	g := New(c, c.Listeners[0], NewUpstream(c, log), Registry(c), readDefaults(c), log)
	g.UseTLS(set.For("admin"))
	server := NewServer(g)
	go func() { _ = server.Serve(tls.NewListener(raw, set.For("admin").Config())) }()
	t.Cleanup(func() { _ = server.Close() })

	if status, _, err := m.get(t, raw.Addr().String(), &admin, "/_ping", nil); err != nil || status != 200 {
		t.Errorf("the pinned client: %d %v", status, err)
	}

	other, _, _ := m.admins.issue(t, client("anyone"))
	if _, _, err := m.get(t, raw.Addr().String(), &other, "/_ping", nil); err == nil {
		t.Error("another client of the CA")
	}
}

// A trusted listener's client CA can't be a scoped one's, by key: a scope's certificate would open it.
func TestTrustLevelsDontShareACA(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")

	// Another file, the same CA's key: a reissued CA certificate is the same CA
	reissued := *m.clients
	tmpl := *m.clients.cert
	tmpl.SerialNumber = big.NewInt(999)
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &m.clients.key.PublicKey, m.clients.key)
	reissued.pem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	m.write(t, "shared.pem", append(append([]byte{}, m.admins.pem...), reissued.pem...))

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n  - name: sites\n    address: tcp://0.0.0.0:2376\n    mode: scoped\n    scopes: " + m.scopes + "\n    tls: {certificate: " + m.dir + "/server.pem, key: " + m.dir + "/server.key, client_ca: " + m.dir + "/clients.pem}\n  - name: admin\n    address: tcp://0.0.0.0:2375\n    mode: trusted\n    allow: {system: read}\n    tls: {certificate: " + m.dir + "/server.pem, key: " + m.dir + "/server.key, client_ca: " + m.dir + "/shared.pem}\n"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := LoadTLS(c, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "listener admin: tls.client_ca: a CA (CN=scopes CA) is also listener sites's, of the other trust level") {
		t.Errorf("a shared CA: %v", err)
	}

	// Becoming shared at a reload: the trusted listener keeps its own CA
	m.write(t, "admins.pem", reissued.pem)
	m.set.Reload()

	if !strings.Contains(m.log.String(), "level=ERROR msg=\"tls files: kept the last good ones\" listener=admin") {
		t.Errorf("the log: %s", m.log.String())
	}

	admin, _, _ := m.admins.issue(t, client("anyone"))
	jane, _, _ := m.clients.issue(t, client("jane"))

	if status, _, err := m.get(t, m.trusted, &admin, "/_ping", nil); err != nil || status != 200 {
		t.Errorf("the admins CA, kept: %d %v", status, err)
	}

	if _, _, err := m.get(t, m.trusted, &jane, "/_ping", nil); err == nil {
		t.Error("a scope's certificate opened the trusted listener after the reload")
	}
}

// The files are read again: what loads is used, what doesn't keeps the last good ones (logged
// once), and a CA that doesn't load never leaves the listener without client verification.
func TestTLSFilesAreReadAgain(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	jane, _, _ := m.clients.issue(t, client("jane"))
	before := m.set.For("sites").Expires()

	served := func() *big.Int {
		conn, err := tls.Dial("tcp", m.sites, m.tlsConfig(&jane))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()

		return conn.ConnectionState().PeerCertificates[0].SerialNumber
	}
	first := served()

	// Unchanged: nothing read again is logged
	m.set.Reload()
	if strings.Contains(m.log.String(), `msg="tls files: read again"`) {
		t.Errorf("an unchanged reload: %s", m.log.String())
	}

	_, certPEM, keyPEM := m.server.issue(t, leaf{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, server: true, notAfter: time.Now().Add(5 * time.Hour)})
	m.write(t, "server.pem", certPEM)
	m.write(t, "server.key", keyPEM)
	m.set.Reload()

	if !strings.Contains(m.log.String(), "level=WARN msg=\"tls certificate expires soon: renew it (it's read again when it changes)\" listener=sites") {
		t.Errorf("no warning of the new certificate's expiry: %s", m.log.String())
	}

	if second := served(); second.Cmp(first) == 0 || !m.set.For("sites").Expires().Before(before) {
		t.Errorf("the new pair isn't used: %s %s", first, second)
	}

	m.write(t, "server.key", []byte("not a key"))
	m.write(t, "clients.pem", []byte("not a CA"))
	m.set.Reload()
	m.set.Reload()

	if n := strings.Count(m.log.String(), "kept the last good ones\" listener=sites"); n != 1 {
		t.Errorf("logged %d times: %s", n, m.log.String())
	}

	if status, _, err := m.get(t, m.sites, &jane, "/_ping", nil); err != nil || status != 200 {
		t.Errorf("jane, with the last good files: %d %v", status, err)
	}

	if _, _, err := m.get(t, m.sites, nil, "/_ping", nil); err == nil {
		t.Error("no client certificate, after a CA that doesn't load")
	}

	// A CA file without a certificate in it is refused as well
	m.write(t, "server.key", keyPEM)
	m.write(t, "clients.pem", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	m.set.Reload()

	if !strings.Contains(m.log.String(), "tls.client_ca: no certificate in it") {
		t.Errorf("the log: %s", m.log.String())
	}

	if _, _, err := m.get(t, m.sites, nil, "/_ping", nil); err == nil {
		t.Error("no client certificate, after an empty CA")
	}
}

// Loading reports each file that doesn't load, by its key.
func TestTLSFilesThatDontLoad(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	listener := func(cert, key, ca string) *config.Config {
		c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n  - name: admin\n    address: tcp://0.0.0.0:2375\n    mode: trusted\n    allow: {system: read}\n    tls: {certificate: " + cert + ", key: " + key + ", client_ca: " + ca + "}\n"))
		if err != nil {
			t.Fatal(err)
		}

		return c
	}

	m.write(t, "bad.pem", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))

	for want, c := range map[string]*config.Config{
		"tls.certificate: open":            listener(m.dir+"/none.pem", m.dir+"/server.key", m.dir+"/admins.pem"),
		"tls.key: open":                    listener(m.dir+"/server.pem", m.dir+"/none.key", m.dir+"/admins.pem"),
		"tls.certificate and tls.key":      listener(m.dir+"/admins.pem", m.dir+"/server.key", m.dir+"/admins.pem"),
		"tls.client_ca: open":              listener(m.dir+"/server.pem", m.dir+"/server.key", m.dir+"/none.pem"),
		"tls.client_ca: x509":              listener(m.dir+"/server.pem", m.dir+"/server.key", m.dir+"/bad.pem"),
		"tls.client_ca: no certificate in": listener(m.dir+"/server.pem", m.dir+"/server.key", m.dir+"/server.key"),
	} {
		if _, err := LoadTLS(c, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "listener admin: "+want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}

// sub is a CA the CA issues: an intermediate.
func (p *pki) sub(t testing.TB, name string) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := x509.ParseCertificate(der)

	return &pki{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// sending is a client certificate sent with these intermediates after it.
func sending(c tls.Certificate, intermediates ...*pki) tls.Certificate {
	c.Certificate = slices.Clone(c.Certificate)
	for _, p := range intermediates {
		c.Certificate = append(c.Certificate, p.cert.Raw)
	}

	return c
}

// twoLevels is a configuration of a scoped listener and a trusted one, with these client CA files.
func (m *mtls) twoLevels(t *testing.T, d *docker, scoped, trusted string) *config.Config {
	t.Helper()

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n  - name: sites\n    address: tcp://0.0.0.0:2376\n    mode: scoped\n    scopes: " + m.scopes + "\n    tls: {certificate: " + m.dir + "/server.pem, key: " + m.dir + "/server.key, client_ca: " + m.dir + "/" + scoped + "}\n  - name: admin\n    address: tcp://0.0.0.0:2375\n    mode: trusted\n    allow: {system: read}\n    tls: {certificate: " + m.dir + "/server.pem, key: " + m.dir + "/server.key, client_ca: " + m.dir + "/" + trusted + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// A CA of one trust level can't sit above or below one of the other: Go verifies a chain through
// the intermediates the client sends, so a scope's certificate under an intermediate of the trusted
// listener's root would open the trusted listener (and the other way round).
func TestTrustLevelsDontChainToEachOther(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	root := newCA(t, "corporate root")
	one := root.sub(t, "intermediate one")
	two := one.sub(t, "intermediate two")
	m.write(t, "root.pem", root.pem)
	m.write(t, "one.pem", one.pem)
	m.write(t, "two-and-one.pem", append(append([]byte{}, two.pem...), one.pem...))

	for _, tc := range []struct {
		name, scoped, trusted, want string
	}{
		{"a scoped intermediate under the trusted root", "one.pem", "root.pem", "listener admin: tls.client_ca: listener sites's CA (CN=intermediate one), of the other trust level, chains up to one here"},
		{"a trusted intermediate under the scoped root", "root.pem", "one.pem", "listener admin: tls.client_ca: a CA (CN=intermediate one) chains up to one of listener sites's"},
		{"two levels down, the one between in the file", "two-and-one.pem", "root.pem", "chains up to one here"},
	} {
		if _, err := LoadTLS(m.twoLevels(t, d, tc.scoped, tc.trusted), slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}

	// Becoming related at a reload: the trusted listener keeps its own CA
	m.write(t, "admins.pem", m.clients.sub(t, "under the scopes CA").pem)
	m.set.Reload()

	if !strings.Contains(m.log.String(), "level=ERROR msg=\"tls files: kept the last good ones\" listener=admin") || !strings.Contains(m.log.String(), "chains up to one of listener sites's") {
		t.Errorf("the log: %s", m.log.String())
	}
}

// A trusted listener takes only a certificate a CA in its client_ca issued directly: an intermediate
// isn't followed, whoever sent it, so a CA above a scoped one (not in its file) opens nothing.
func TestATrustedClientIsIssuedDirectly(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	root := newCA(t, "corporate root")
	one := root.sub(t, "intermediate one")
	two := one.sub(t, "intermediate two")
	m.write(t, "root.pem", root.pem)
	m.write(t, "two.pem", two.pem)

	// Loads: the file has two, not the one between it and the root
	c := m.twoLevels(t, d, "two.pem", "root.pem")
	set, err := LoadTLS(c, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	log := slog.New(slog.DiscardHandler)
	g := New(c, c.Listeners[1], NewUpstream(c, log), Registry(c), readDefaults(c), log)
	g.UseTLS(set.For("admin"))
	server := NewServer(g)
	go func() { _ = server.Serve(tls.NewListener(raw, set.For("admin").Config())) }()
	t.Cleanup(func() { _ = server.Close() })

	admin, _, _ := root.issue(t, client("orchestrator"))
	janeUnderOne, _, _ := one.issue(t, client("jane"))
	janeUnderTwo, _, _ := two.issue(t, client("jane"))

	for _, tc := range []struct {
		name  string
		cert  tls.Certificate
		opens bool
	}{
		{"the root's own", admin, true},
		{"the root's own, padded with intermediates", sending(admin, two, one), true},
		{"under an intermediate it sends", sending(janeUnderOne, one), false},
		{"a scope's, two levels down, sending both", sending(janeUnderTwo, two, one), false},
		{"a scope's, padded once more", sending(janeUnderTwo, two, one, two), false},
	} {
		status, _, err := m.get(t, raw.Addr().String(), &tc.cert, "/_ping", nil)
		if opened := err == nil && status == 200; opened != tc.opens {
			t.Errorf("%s: opened %v (%d %v)", tc.name, opened, status, err)
		}
	}
}

// A client certificate is checked on each request, not only at its connection's handshake: on a
// connection kept alive, a certificate that expired, or whose CA was removed, is refused; and its
// streams end. On both trust levels.
func TestACertificateIsCheckedAfterItsHandshake(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(m *mtls, cert tls.Certificate)
	}{
		{"expired", func(m *mtls, cert tls.Certificate) {
			expires := cert.Leaf.NotAfter
			clock = func() time.Time { return expires.Add(time.Second) }
		}},
		{"its CA removed", func(m *mtls, _ tls.Certificate) {
			m.write(t, "clients.pem", newCA(t, "the new scopes CA").pem)
			m.write(t, "admins.pem", newCA(t, "the new admins CA").pem)
			m.set.Reload()
		}},
	} {
		for _, level := range []string{"scoped", "trusted"} {
			t.Run(tc.name+" on "+level, func(t *testing.T) {
				t.Cleanup(func() { clock = time.Now })
				d := startDocker(t)
				m := mtlsGate(t, d, "")
				address, path, g, cert := m.sites, "/v1.56/exec/exec-jane/json", m.gates[0], tls.Certificate{}

				if level == "scoped" {
					cert, _, _ = m.clients.issue(t, client("jane"))
				} else {
					address, path, g = m.trusted, "/_ping", m.gates[1]
					cert, _, _ = m.admins.issue(t, client("orchestrator"))
				}

				// One connection, kept alive
				var reused []bool
				trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = append(reused, i.Reused) }}
				keptAlive := &http.Client{Transport: &http.Transport{TLSClientConfig: m.tlsConfig(&cert), MaxConnsPerHost: 1}, Timeout: 5 * time.Second}
				send := func() int {
					req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), "GET", "https://"+address+path, nil)
					res, err := keptAlive.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()

					return res.StatusCode
				}

				if status := send(); status != 200 {
					t.Fatalf("before: %d", status)
				}

				conn, reader := m.tlsStream(t, address, "exec-jane", cert)

				tc.change(m, cert)

				if status := send(); status != http.StatusUnauthorized {
					t.Errorf("after, on the connection kept alive: %d", status)
				}

				if len(reused) != 2 || !reused[1] {
					t.Errorf("the connection wasn't kept alive: %v", reused)
				}

				g.Revoke()

				if !ended(t, conn, reader) {
					t.Error("its stream is still open")
				}
			})
		}
	}
}

// On a scoped listener a client certificate needs its scope: without one, admits takes nothing. A
// trusted listener's needs none.
func TestAScopedListenerAdmitsNoCertificateWithoutItsScope(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	jane, _, _ := m.clients.issue(t, client("jane"))
	admin, _, _ := m.admins.issue(t, client("orchestrator"))
	of := func(c tls.Certificate, ca *pki) credential {
		return credential{key: SPKI(c.Leaf), chains: []verifiedChain{{ca: SPKI(ca.cert), expires: c.Leaf.NotAfter}}}
	}

	scope, err := m.gate.scopes.Get("jane")
	if err != nil {
		t.Fatal(err)
	}

	if sites := m.set.For("sites"); sites.admits(of(jane, m.clients), nil) || !sites.admits(of(jane, m.clients), scope) {
		t.Error("the scoped listener: a certificate without its scope, or not with it")
	}

	if !m.set.For("admin").admits(of(admin, m.admins), nil) {
		t.Error("the trusted listener")
	}

	if (*TLSFiles)(nil).admits(of(admin, m.admins), scope) {
		t.Error("a gate without its listener's files")
	}
}
