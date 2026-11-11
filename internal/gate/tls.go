package gate

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// TLSFiles is a TCP listener's certificate, key and client CA, as last read: read again at each
// scan, and swapped in only when they load. A pair or a CA that doesn't load keeps the last good
// one, so a listener never falls back to no client verification.
type TLSFiles struct {
	listener config.Listener
	current  atomic.Pointer[tlsState]
	failed   string // the last reload's error, logged once
}

type tlsState struct {
	cert  tls.Certificate
	leaf  *x509.Certificate
	pool  *x509.CertPool             // nil without client_ca
	cas   map[[sha256.Size]byte]bool // the client CAs' public keys
	certs []*x509.Certificate        // the client CAs
	files [3][]byte
}

// SPKI is a certificate's public key as pins name it: the SHA-256 of its SubjectPublicKeyInfo.
func SPKI(c *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(c.RawSubjectPublicKeyInfo)
}

// read loads the listener's files. Client CAs related to those of a listener of the other trust level
// (others, by name) aren't loaded: see apart.
func (t *TLSFiles) read(others map[string]*tlsState) (*tlsState, error) {
	files := t.listener.TLS
	st := &tlsState{}

	var err error
	if st.files[0], err = os.ReadFile(files.Certificate); err != nil {
		return nil, fmt.Errorf("tls.certificate: %w", err)
	}

	if st.files[1], err = os.ReadFile(files.Key); err != nil {
		return nil, fmt.Errorf("tls.key: %w", err)
	}

	if st.cert, err = tls.X509KeyPair(st.files[0], st.files[1]); err != nil {
		return nil, fmt.Errorf("tls.certificate and tls.key: %w", err)
	}

	st.leaf = st.cert.Leaf

	if files.ClientCA == "" {
		return st, nil
	}

	if st.files[2], err = os.ReadFile(files.ClientCA); err != nil {
		return nil, fmt.Errorf("tls.client_ca: %w", err)
	}

	st.pool = x509.NewCertPool()
	st.cas = map[[sha256.Size]byte]bool{}

	for rest := st.files[2]; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tls.client_ca: %w", err)
		}

		st.pool.AddCert(ca)
		st.cas[SPKI(ca)] = true
		st.certs = append(st.certs, ca)
	}

	if len(st.cas) == 0 {
		return nil, errors.New("tls.client_ca: no certificate in it")
	}

	for name, other := range others {
		if err := apart(st, other, name); err != nil {
			return nil, fmt.Errorf("tls.client_ca: %w", err)
		}
	}

	return st, nil
}

// apart is an error when a listener's client CAs are related to those of a listener of the other
// trust level (named other): one of them is the other's (by key), or chains up to it, either way.
// Go verifies a client's chain through the intermediates the client sends, so a scope's certificate
// under an intermediate whose root is the trusted listener's would open the trusted listener.
func apart(own, other *tlsState, name string) error {
	intermediates := x509.NewCertPool()
	for _, ca := range append(slices.Clone(own.certs), other.certs...) {
		intermediates.AddCert(ca)
	}

	below := func(ca *x509.Certificate, roots *x509.CertPool) bool {
		_, err := ca.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})

		return err == nil
	}

	for _, ca := range own.certs {
		if other.cas[SPKI(ca)] {
			return fmt.Errorf("a CA (%s) is also listener %s's, of the other trust level: a client certificate it issues for a scope would then open the trusted listener", ca.Subject, name)
		}

		if below(ca, other.pool) {
			return fmt.Errorf("a CA (%s) chains up to one of listener %s's, of the other trust level: give each trust level its own root", ca.Subject, name)
		}
	}

	for _, ca := range other.certs {
		if below(ca, own.pool) {
			return fmt.Errorf("listener %s's CA (%s), of the other trust level, chains up to one here: give each trust level its own root", name, ca.Subject)
		}
	}

	return nil
}

// Config is the listener's TLS configuration: TLS 1.3, the files as last read, and with client_ca,
// a client certificate from that CA alone (never the system's), for client authentication.
func (t *TLSFiles) Config() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			st := t.current.Load()
			// No session tickets: a resumed session would skip the client certificate's
			// verification against the CA as it is now
			c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{st.cert}, SessionTicketsDisabled: true}

			if st.pool != nil {
				c.ClientAuth = tls.RequireAndVerifyClientCert
				c.ClientCAs = st.pool
				c.VerifyConnection = t.verify
			}

			return c, nil
		},
	}
}

// verify takes a client certificate only when it says it's for client authentication: one without
// extended key usages would otherwise do (a server's certificate from the same CA included). On a
// trusted listener, a CA in client_ca must have issued it directly, with no intermediate, and with
// clients, its public key must be one of them.
func (t *TLSFiles) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("no client certificate")
	}

	leaf := cs.PeerCertificates[0]
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return errors.New("the client certificate isn't for client authentication (extended key usage clientAuth)")
	}

	if t.listener.Mode != config.Trusted {
		return nil
	}

	for _, chain := range cs.VerifiedChains {
		if len(chain) != 2 {
			return errors.New("a trusted listener's client certificate must be issued directly by a CA in its client_ca, not through an intermediate")
		}
	}

	if len(t.listener.Clients) == 0 {
		return nil
	}

	key := SPKI(leaf)
	for _, c := range t.listener.Clients {
		if c.SHA256 == hex.EncodeToString(key[:]) {
			return nil
		}
	}

	return errors.New("the client certificate's public key isn't one of the listener's clients")
}

// credential is what a client certificate was taken with: its public key, and each chain it was
// verified by, as the CA it ends at and when the first of its certificates expires.
type credential struct {
	key    [sha256.Size]byte
	chains []verifiedChain
}

type verifiedChain struct {
	ca      [sha256.Size]byte
	expires time.Time
}

// credentialOf is the credential of a connection's verified client certificate (false without one).
func credentialOf(cs *tls.ConnectionState) (credential, bool) {
	if cs == nil || len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
		return credential{}, false
	}

	c := credential{key: SPKI(cs.PeerCertificates[0])}

	for _, chain := range cs.VerifiedChains {
		v := verifiedChain{ca: SPKI(chain[len(chain)-1]), expires: chain[0].NotAfter}
		for _, cert := range chain {
			if cert.NotAfter.Before(v.expires) {
				v.expires = cert.NotAfter
			}
		}

		c.chains = append(c.chains, v)
	}

	return c, true
}

// admits says whether a client certificate, verified at its connection's handshake, still opens the
// listener now: one of its chains ends at a CA still in client_ca, and none of that chain's
// certificates has expired; on a scoped listener, its scope (s) still pins it. Each request is
// checked with it, and each stream at each scan: a connection kept alive, or a stream, outlives
// its handshake.
func (t *TLSFiles) admits(c credential, s *scope.Scope) bool {
	if t == nil || t.listener.Mode == config.Scoped && (s == nil || !s.Pinned(c.key)) {
		return false
	}

	cas, now := t.current.Load().cas, clock()
	for _, chain := range c.chains {
		if cas[chain.ca] && now.Before(chain.expires) {
			return true
		}
	}

	return false
}

// Expires is when the certificate in use expires.
func (t *TLSFiles) Expires() time.Time {
	return t.current.Load().leaf.NotAfter
}

// TLS is the TLS files of every listener that has them.
type TLS struct {
	files map[string]*TLSFiles
	log   *slog.Logger
}

// LoadTLS reads every listener's TLS files. A client CA a trusted listener shares with a scoped one,
// or that sits above or below one, is an error: a scope's certificate would open the trusted
// listener.
func LoadTLS(c *config.Config, log *slog.Logger) (*TLS, error) {
	set := &TLS{files: map[string]*TLSFiles{}, log: log}

	for _, l := range c.Listeners {
		if l.TLS == nil {
			continue
		}

		t := &TLSFiles{listener: l}

		st, err := t.read(set.others(l))
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.Name, err)
		}

		t.current.Store(st)
		set.files[l.Name] = t
		set.expiring(l.Name, st)
	}

	return set, nil
}

// ExpiresSoon is how long before its certificate expires a listener is warned about.
const ExpiresSoon = 14 * 24 * time.Hour

// expiring warns of a certificate in use that expires soon.
func (s *TLS) expiring(listener string, st *tlsState) {
	if time.Until(st.leaf.NotAfter) < ExpiresSoon {
		s.log.Warn("tls certificate expires soon: renew it (it's read again when it changes)", "listener", listener, "expires", st.leaf.NotAfter)
	}
}

// For is a listener's TLS files (nil without tls).
func (s *TLS) For(listener string) *TLSFiles {
	return s.files[listener]
}

// others is the files in use of the listeners of the other trust level that have a client CA, by
// name.
func (s *TLS) others(l config.Listener) map[string]*tlsState {
	others := map[string]*tlsState{}

	for name, t := range s.files {
		if st := t.current.Load(); t.listener.Mode != l.Mode && name != l.Name && st.pool != nil {
			others[name] = st
		}
	}

	return others
}

// Reload reads each listener's files again. What changed and loads is swapped in; what doesn't load
// keeps the last good files, and is logged at error level once.
func (s *TLS) Reload() {
	for name, t := range s.files {
		st, err := t.read(s.others(t.listener))
		if err != nil {
			if t.failed != err.Error() {
				s.log.Error("tls files: kept the last good ones", "listener", name, "error", err)
				t.failed = err.Error()
			}

			continue
		}

		t.failed = ""

		if sameFiles(t.current.Load().files, st.files) {
			continue
		}

		t.current.Store(st)
		s.log.Info("tls files: read again", "listener", name, "expires", st.leaf.NotAfter)
		s.expiring(name, st)
	}
}

func sameFiles(a, b [3][]byte) bool {
	return bytes.Equal(a[0], b[0]) && bytes.Equal(a[1], b[1]) && bytes.Equal(a[2], b[2])
}

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// certificateScope is the scope a client certificate names: its subject's one common name, exactly
// a scope's name.
func certificateScope(c *x509.Certificate) (string, error) {
	var names []string

	for _, a := range c.Subject.Names {
		if a.Type.Equal(oidCommonName) {
			v, _ := a.Value.(string)
			names = append(names, v)
		}
	}

	switch {
	case len(names) != 1:
		return "", fmt.Errorf("its subject has %d common names: a scope's certificate has exactly one, the scope's name", len(names))
	case !scope.ValidName(names[0]):
		return "", fmt.Errorf("its common name %q isn't a scope's name", strings.ToValidUTF8(names[0], "?"))
	}

	return names[0], nil
}
