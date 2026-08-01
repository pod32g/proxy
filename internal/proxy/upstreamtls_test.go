package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pod32g/proxy/internal/config"
)

// testPKI is a throwaway certificate authority and the leaves it issues.
// Everything is in-process, because the point is to prove the trust plumbing
// works against a CA the system store has never heard of — which is exactly the
// situation an internal service with a private PKI presents.
type testPKI struct {
	dir     string
	caPath  string
	caPool  *x509.CertPool
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caBytes []byte
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "proxy-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	return &testPKI{dir: dir, caPath: caPath, caPool: pool, caCert: cert, caKey: key, caBytes: caPEM}
}

// issue mints a leaf certificate valid for 127.0.0.1 and writes it to disk.
func (p *testPKI) issue(t *testing.T, name string) (certPath, keyPath string, pair tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost", name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(p.dir, name+".crt")
	keyPath = filepath.Join(p.dir, name+".key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pair, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return certPath, keyPath, pair
}

// mTLSBackend starts an HTTPS server that demands a client certificate signed
// by the test CA.
func (p *testPKI) mTLSBackend(t *testing.T, body string) *httptest.Server {
	t.Helper()
	_, _, serverPair := p.issue(t, "backend")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.caPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The whole point of the ticket: an internal service behind a private PKI that
// also demands a client certificate. Before this, the honest answer was that it
// could not be reached at all.
func TestReverseProxyReachesAnMTLSBackend(t *testing.T) {
	pki := newPKI(t)
	backend := pki.mTLSBackend(t, "REACHED")

	certPath, keyPath, _ := pki.issue(t, "client")
	upstream := config.UpstreamTLS{CAFile: pki.caPath, CertFile: certPath, KeyFile: keyPath}
	tlsCfg, err := upstream.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}

	target, _ := url.Parse(backend.URL)
	rp := New(target, newLogger(), func(string) map[string]string { return nil }, tlsCfg)
	front := httptest.NewServer(rp)
	defer front.Close()

	resp, err := http.Get(front.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "REACHED" {
		t.Errorf("body = %q, want REACHED", got)
	}
}

// Without the private CA the backend is untrusted, and without the client
// certificate it refuses the handshake. Both have to fail, or the test above
// proves nothing about whether the material was used.
func TestMTLSBackendIsUnreachableWithoutTheMaterial(t *testing.T) {
	pki := newPKI(t)
	backend := pki.mTLSBackend(t, "REACHED")
	certPath, keyPath, _ := pki.issue(t, "client")

	for name, upstream := range map[string]config.UpstreamTLS{
		"nothing configured":           {},
		"CA but no client certificate": {CAFile: pki.caPath},
		"client certificate but no CA": {CertFile: certPath, KeyFile: keyPath},
	} {
		t.Run(name, func(t *testing.T) {
			tlsCfg, err := upstream.BuildTLSConfig()
			if err != nil {
				t.Fatalf("BuildTLSConfig: %v", err)
			}
			target, _ := url.Parse(backend.URL)
			rp := New(target, newLogger(), func(string) map[string]string { return nil }, tlsCfg)
			front := httptest.NewServer(rp)
			defer front.Close()

			resp, err := http.Get(front.URL)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Error("the backend was reached without the required TLS material")
			}
			if resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", resp.StatusCode)
			}
		})
	}
}

// Forward mode sees TLS itself only for absolute-form https requests; CONNECT
// tunnels are opaque and the client does its own handshake. The absolute-form
// path has to honour the material too.
func TestForwardProxyUsesUpstreamTLSForAbsoluteFormHTTPS(t *testing.T) {
	pki := newPKI(t)
	backend := pki.mTLSBackend(t, "REACHED")
	certPath, keyPath, _ := pki.issue(t, "client")

	tlsCfg, err := config.UpstreamTLS{
		CAFile: pki.caPath, CertFile: certPath, KeyFile: keyPath,
	}.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts(), UpstreamTLS: tlsCfg})

	// Driven against the handler directly rather than through an http.Client.
	// Go's transport uses CONNECT for https through a proxy, so a client can
	// never produce the absolute-form https request this path exists to serve —
	// and a test that went through one would be measuring the client's tunnel,
	// not the proxy's own handshake.
	req := httptest.NewRequest("GET", backend.URL+"/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "REACHED" {
		t.Errorf("body = %q, want REACHED", body)
	}
}

// And the same path must fail without the material, or the test above proves
// only that the request was made.
func TestForwardProxyWithoutUpstreamTLSCannotReachTheBackend(t *testing.T) {
	pki := newPKI(t)
	backend := pki.mTLSBackend(t, "REACHED")

	h := NewForward(newLogger(), func(string) map[string]string { return nil },
		Policy{AllowPrivate: true, ConnectPorts: allPorts()})

	req := httptest.NewRequest("GET", backend.URL+"/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("reached a private-PKI backend with no trust material configured")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}
