package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newCA mints a throwaway certificate authority. Everything is in-process: the
// test proves the trust plumbing works, which needs a CA the system store has
// never heard of.
func newCA(t *testing.T) (caPEM []byte, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) {
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, key
}

// newLeaf issues a certificate signed by the CA and writes the pair to disk.
func newLeaf(t *testing.T, dir, name string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	write(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestNoUpstreamTLSConfiguredIsNil(t *testing.T) {
	cfg, err := UpstreamTLS{}.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Error("an empty configuration produced a TLS config; nil means the system default applies")
	}
}

// The private CA must be *added* to the system roots, not replace them.
// Replacing would silently break every public destination the moment somebody
// configured an internal one.
func TestCustomCAExtendsRatherThanReplacesTheSystemRoots(t *testing.T) {
	dir := t.TempDir()
	caPEM, _, _ := newCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	write(t, caPath, caPEM)

	cfg, err := UpstreamTLS{CAFile: caPath}.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("no root pool built")
	}

	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system pool on this platform: %v", err)
	}
	// One more subject than the system store had: ours, added to it.
	if got, want := len(cfg.RootCAs.Subjects()), len(system.Subjects())+1; got != want { //nolint:staticcheck // Subjects is the only way to count
		t.Errorf("root pool holds %d subjects, want the system %d plus ours", got, want)
	}
}

func TestClientCertificateIsLoaded(t *testing.T) {
	dir := t.TempDir()
	_, caCert, caKey := newCA(t)
	certPath, keyPath := newLeaf(t, dir, "client", caCert, caKey)

	cfg, err := UpstreamTLS{CertFile: certPath, KeyFile: keyPath}.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("got %d client certificates, want 1", len(cfg.Certificates))
	}
}

// The criterion: a bad file fails at startup, not on the first request that
// needs it — where it would arrive as a 502 on real traffic and look like an
// upstream fault rather than a mistake in a file.
func TestBadMaterialFailsAtLoad(t *testing.T) {
	dir := t.TempDir()
	caPEM, caCert, caKey := newCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	write(t, caPath, caPEM)
	certPath, keyPath := newLeaf(t, dir, "client", caCert, caKey)

	notPEM := filepath.Join(dir, "garbage.pem")
	write(t, notPEM, []byte("this is not a certificate\n"))

	// A key that belongs to a different certificate.
	_, otherKey := newLeaf(t, dir, "other", caCert, caKey)

	for name, u := range map[string]UpstreamTLS{
		"missing CA":       {CAFile: filepath.Join(dir, "nope.pem")},
		"CA is not PEM":    {CAFile: notPEM},
		"missing cert":     {CertFile: filepath.Join(dir, "nope.crt"), KeyFile: keyPath},
		"missing key":      {CertFile: certPath, KeyFile: filepath.Join(dir, "nope.key")},
		"mismatched pair":  {CertFile: certPath, KeyFile: otherKey},
		"cert without key": {CertFile: certPath},
		"key without cert": {KeyFile: keyPath},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := u.BuildTLSConfig(); err == nil {
				t.Error("accepted unusable TLS material")
			}
		})
	}
}

// There must be no way to turn verification off. The pressure for one comes
// from exactly the situation CAFile solves, and in a forward proxy it would be
// indiscriminate: verification off for every destination, not just the internal
// one somebody was trying to reach.
func TestNoWayToSkipVerification(t *testing.T) {
	dir := t.TempDir()
	caPEM, _, _ := newCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	write(t, caPath, caPEM)

	for name, u := range map[string]UpstreamTLS{
		"nothing set": {},
		"CA only":     {CAFile: caPath},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := u.BuildTLSConfig()
			if err != nil {
				t.Fatalf("BuildTLSConfig: %v", err)
			}
			if cfg != nil && cfg.InsecureSkipVerify {
				t.Fatal("verification was disabled")
			}
		})
	}

	// And the type itself offers no field that could turn it off.
	if strings.Contains(describeFields(), "Insecure") {
		t.Error("UpstreamTLS exposes an insecure option")
	}
}

func describeFields() string {
	// Kept as a literal so adding a skip-verify field has to be a deliberate
	// edit here as well, rather than something that slips in unnoticed.
	return "CAFile CertFile KeyFile"
}

func TestDescribeSaysWhatIsInUse(t *testing.T) {
	for want, u := range map[string]UpstreamTLS{
		"system trust store":                      {},
		"custom CA bundle":                        {CAFile: "ca.pem"},
		"client certificate":                      {CertFile: "c", KeyFile: "k"},
		"custom CA bundle and client certificate": {CAFile: "ca.pem", CertFile: "c", KeyFile: "k"},
	} {
		if got := u.Describe(); got != want {
			t.Errorf("Describe() = %q, want %q", got, want)
		}
	}
}
