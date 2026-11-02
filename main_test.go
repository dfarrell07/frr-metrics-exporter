// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var discard = slog.New(slog.DiscardHandler)

// pki issues certificates from one throwaway CA.
type pki struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	pem   []byte
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &pki{ca, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns PEM cert and key for cn, usable as server (127.0.0.1) and client.
func (p *pki) issue(t *testing.T, cn string, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// start runs the server and returns its address and a stop function that
// checks the server exits cleanly.
func start(t *testing.T, c config) (string, func()) {
	t.Helper()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	c.listen = l.Addr().String()
	l.Close()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, &tlsSource{cfg: c, logger: discard}, h, discard) }()
	for i := 0; i < 100; i++ {
		if conn, err := net.Dial("tcp", c.listen); err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return c.listen, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run returned %v on shutdown", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("run did not return after cancel")
		}
	}
}

func get(addr string, tc *tls.Config) (*x509.Certificate, error) {
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 5 * time.Second}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("https://" + addr + "/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp.TLS.PeerCertificates[0], nil
}

func TestMutualTLSAndRotation(t *testing.T) {
	p, dir := newPKI(t), t.TempDir()
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), clientCAFile: filepath.Join(dir, "ca.crt")}
	crt, key := p.issue(t, "server-1", 2)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	write(t, cfg.clientCAFile, p.pem)

	addr, stop := start(t, cfg)
	defer stop()

	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	cc, ck := p.issue(t, "scraper", 3)
	clientPair, _ := tls.X509KeyPair(cc, ck)

	if _, err := get(addr, &tls.Config{RootCAs: roots}); err == nil {
		t.Error("a client without a certificate was served")
	}
	other := newPKI(t)
	oc, ok := other.issue(t, "intruder", 4)
	intruder, _ := tls.X509KeyPair(oc, ok)
	if _, err := get(addr, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{intruder}}); err == nil {
		t.Error("a client certificate from another CA was served")
	}
	good := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientPair}}
	if cert, err := get(addr, good); err != nil || cert.Subject.CommonName != "server-1" {
		t.Fatalf("scrape with a valid client certificate: cert=%v err=%v", cert, err)
	}

	// Rotate: the next handshake presents the new certificate with no restart.
	crt, key = p.issue(t, "server-2", 5)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	if cert, err := get(addr, good); err != nil || cert.Subject.CommonName != "server-2" {
		t.Fatalf("after rotation: cert=%v err=%v", cert, err)
	}

	// A corrupt rotation keeps serving the last good certificate.
	write(t, cfg.certFile, []byte("garbage"))
	if cert, err := get(addr, good); err != nil || cert.Subject.CommonName != "server-2" {
		t.Fatalf("after corrupt rotation: cert=%v err=%v", cert, err)
	}

	// An emptied CA file must not turn client authentication off.
	write(t, cfg.clientCAFile, nil)
	if _, err := get(addr, &tls.Config{RootCAs: roots}); err == nil {
		t.Error("an emptied CA file disabled client authentication")
	}

	// Recover from the corrupt file, then rotate the client CA: the old scraper is refused, one from the new CA is served.
	np := newPKI(t)
	crt, key = p.issue(t, "server-3", 7)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	write(t, cfg.clientCAFile, np.pem)
	if _, err := get(addr, good); err == nil {
		t.Error("a client from the replaced CA was still served")
	}
	nc, nk := np.issue(t, "scraper-2", 6)
	newPair, _ := tls.X509KeyPair(nc, nk)
	if _, err := get(addr, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{newPair}}); err != nil {
		t.Errorf("a client from the new CA was refused: %v", err)
	}
}

func TestStartupRejectsBadTLSInput(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	write(t, empty, nil)
	missing := filepath.Join(dir, "missing")
	for name, c := range map[string]config{
		"missing key pair": {certFile: missing, keyFile: missing},
		"empty key pair":   {certFile: empty, keyFile: empty},
	} {
		if _, err := (&tlsSource{cfg: c, logger: discard}).get(nil); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	p := newPKI(t)
	crt, key := p.issue(t, "s", 2)
	write(t, filepath.Join(dir, "c"), crt)
	write(t, filepath.Join(dir, "k"), key)
	c := config{certFile: filepath.Join(dir, "c"), keyFile: filepath.Join(dir, "k"), clientCAFile: empty}
	if _, err := (&tlsSource{cfg: c, logger: discard}).get(nil); err == nil {
		t.Error("empty client CA file: want error")
	}
}

func TestCheckListen(t *testing.T) {
	for addr, ca := range map[string]string{
		"127.0.0.1:9141": "", "[::1]:9141": "", "localhost:9141": "",
		"0.0.0.0:9141": "ca", "10.0.0.5:9141": "ca",
	} {
		if err := checkListen(config{listen: addr, clientCAFile: ca}); err != nil {
			t.Errorf("%s with ca=%q: %v", addr, ca, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:9141", ":9141", "10.0.0.5:9141", "example.com:9141", "bad"} {
		if err := checkListen(config{listen: addr}); err == nil {
			t.Errorf("%s without a client CA: want error", addr)
		}
	}
}

// A scrape still running when the grace period ends is cancelled, which is what
// kills its vtysh, and run reports that it did not drain.
func TestShutdownCancelsScrapesAfterGrace(t *testing.T) {
	p, dir := newPKI(t), t.TempDir()
	crt, key := p.issue(t, "server", 2)
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), grace: 200 * time.Millisecond}
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg.listen = l.Addr().String()
	l.Close()

	started, cancelled := make(chan struct{}), make(chan struct{})
	e := newExporter(func(ctx context.Context, _ string) ([]byte, error) {
		close(started)
		<-ctx.Done()                       // a hung vtysh
		time.Sleep(300 * time.Millisecond) // taking its time to die
		close(cancelled)
		return nil, ctx.Err()
	}, time.Minute)
	e.cs = e.cs[:1]

	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, &tlsSource{cfg: cfg, logger: discard}, e, discard) }()
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", cfg.listen); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A client that outlasts the test, so only the server can cut the scrape off.
	patient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: time.Minute}
	go patient.Get("https://" + cfg.listen + "/") //nolint:errcheck // the scrape is cut off by design
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("scrape never reached FRR")
	}
	stop()
	select {
	case err := <-done:
		if err == nil {
			t.Error("run reported a clean drain with a scrape still running")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the grace period")
	}
	// run waits for the read to end, so no vtysh outlives the exporter.
	select {
	case <-cancelled:
	default:
		t.Error("run returned before the in-flight read was cancelled")
	}
}

// logs records what a slog logger writes.
type logs struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.buf.String(), substr)
}

func gauge(t *testing.T, c prometheus.Collector, name string) float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f.Metric[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("no series %s", name)
	return 0
}

func TestTLSReloadHealthIsVisibleAndLoggedOnce(t *testing.T) {
	p, dir := newPKI(t), t.TempDir()
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), clientCAFile: filepath.Join(dir, "ca.crt")}
	crt, key := p.issue(t, "server", 2)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	write(t, cfg.clientCAFile, p.pem)
	var out logs
	src := &tlsSource{cfg: cfg, logger: slog.New(slog.NewTextHandler(&out, nil))}

	first, err := src.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := gauge(t, src, "frrk8s_exporter_tls_config_current"); v != 1 {
		t.Errorf("current = %v, want 1", v)
	}
	if got, want := gauge(t, src, "frrk8s_exporter_tls_cert_not_after_timestamp_seconds"), float64(first.Certificates[0].Leaf.NotAfter.Unix()); got != want {
		t.Errorf("not_after = %v, want %v", got, want)
	}

	// Deleting the CA must not turn client authentication off, and must show.
	os.Remove(cfg.clientCAFile)
	for i := 0; i < 5; i++ {
		got, err := src.get(nil)
		if err != nil || got != first {
			t.Fatalf("handshake %d: config changed or failed (%v)", i, err)
		}
	}
	if v := gauge(t, src, "frrk8s_exporter_tls_config_current"); v != 0 {
		t.Errorf("current = %v after a failed reload, want 0", v)
	}
	if n := out.count("TLS reload failed"); n != 1 {
		t.Errorf("reload failure logged %d times, want once", n)
	}

	np := newPKI(t)
	write(t, cfg.clientCAFile, np.pem)
	got, err := src.get(nil)
	if err != nil || got == first {
		t.Fatalf("recovery: config not rebuilt (%v)", err)
	}
	if v := gauge(t, src, "frrk8s_exporter_tls_config_current"); v != 1 || out.count("TLS configuration reloaded") != 1 {
		t.Errorf("recovery not reported: current=%v, logs %d", v, out.count("TLS configuration reloaded"))
	}
}

func TestTLSFilesAreReadAtMostOncePerRecheck(t *testing.T) {
	p, dir := newPKI(t), t.TempDir()
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), recheck: time.Hour}
	crt, key := p.issue(t, "one", 2)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	src := &tlsSource{cfg: cfg, logger: discard}
	first, _ := src.get(nil)
	crt, key = p.issue(t, "two", 3)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	if again, _ := src.get(nil); again != first {
		t.Error("files were re-read inside the recheck interval")
	}
}
