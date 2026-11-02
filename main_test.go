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
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var discard = slog.New(slog.DiscardHandler)

func TestScrapeTimeoutFlagBounds(t *testing.T) {
	args, flags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = args, flags })
	maxTimeout := time.Duration(1<<63-1) - 5*time.Second
	for _, timeout := range []time.Duration{-1, 0, 100 * time.Millisecond, maxTimeout, maxTimeout + 1, time.Duration(1<<63 - 1)} {
		t.Run(timeout.String(), func(t *testing.T) {
			flag.CommandLine = flag.NewFlagSet("exporter", flag.ContinueOnError)
			os.Args = []string{"exporter", "--tls-cert-file=server.crt", "--tls-key-file=server.key", "--scrape-timeout=" + timeout.String()}
			c, _, err := parseFlags()
			valid := timeout > 0 && timeout <= maxTimeout
			if (err == nil) != valid || c.timeout != timeout {
				t.Fatalf("timeout %v: config=%v, error=%v, want valid=%v", timeout, c.timeout, err, valid)
			}
		})
	}
}

func TestMainUsesConfiguredScrapeTimeout(t *testing.T) {
	// Re-enter the real startup path in a child, including flags, runner and TLS.
	if os.Getenv("FRR_TEST_EXPORTER_MAIN") == "1" {
		os.Args = append(os.Args[:1], os.Args[3:]...) // discard -test.run and --
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		return
	}
	p, dir := newPKI(t), t.TempDir()
	crt, key := p.issue(t, "server", 2)
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	write(t, certFile, crt)
	write(t, keyFile, key)
	vtysh, pidFile := filepath.Join(dir, "vtysh"), filepath.Join(dir, "pid")
	write(t, vtysh, []byte("#!/bin/sh\necho $$ > \"$FRR_TEST_PID_FILE\"\nexec sleep 30\n"))
	if err := os.Chmod(vtysh, 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainUsesConfiguredScrapeTimeout$", "--",
		"--listen="+addr, "--tls-cert-file="+certFile, "--tls-key-file="+keyFile,
		"--collectors=bgp", "--vtysh="+vtysh, "--scrape-timeout=100ms")
	cmd.Env = append(os.Environ(), "FRR_TEST_EXPORTER_MAIN=1", "FRR_TEST_PID_FILE="+pidFile)
	var output logs
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		// Kill the direct child as well on failure, so a mutant cannot leak it.
		if t.Failed() {
			if data, err := os.ReadFile(pidFile); err == nil {
				var pid int
				if _, err := fmt.Sscan(string(data), &pid); err == nil {
					syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
		if err := cmd.Wait(); err != nil {
			t.Errorf("exporter exit: %v", err)
		}
		if t.Failed() {
			t.Log(output.buf.String()) // Wait has finished all writes.
		}
	})
	for i := 0; ; i++ {
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		if i == 100 {
			t.Fatal("exporter did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	start := time.Now()
	// No Prometheus timeout header: only --scrape-timeout can bound this read.
	resp, err := client.Get("https://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || time.Since(start) > 2*time.Second ||
		!strings.Contains(string(body), `frrk8s_scrape_collector_success{collector="bgp"} 0`) {
		t.Fatalf("scrape after %v: status=%d, error=%v, body=%s", time.Since(start), resp.StatusCode, err, body)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Sscan(string(data), &pid); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("vtysh child %d still exists after scrape: %v", pid, err)
	}
}

func TestSmokeOnlyCleansResourcesItOwns(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go":      "exit 0",
		"openssl": "exit 0",
		"podman": `printf '%s\n' "$*" >> "$SMOKE_TEST_LOG"
if [ "$1" = network ] && [ "$2" = create ] && [ "$SMOKE_TEST_FAIL_AT" = network ]; then exit 1; fi
if [ "$1" = run ] || [ "$1" = rm ]; then exit 1; fi`,
	} {
		path := filepath.Join(dir, name)
		write(t, path, []byte("#!/bin/sh\n"+body+"\n"))
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var previous string
	for _, failAt := range []string{"network", "network", "run"} {
		log := filepath.Join(t.TempDir(), "podman.log")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "bash", "hack/smoke.sh")
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SMOKE_TEST_LOG="+log, "SMOKE_TEST_FAIL_AT="+failAt)
		out, err := cmd.CombinedOutput()
		cancel()
		if err == nil || ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("smoke: error %v, output %s", err, out)
		}
		calls, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
		if !strings.HasPrefix(lines[0], "network create ") {
			t.Fatalf("network creation not attempted: %s", calls)
		}
		if failAt == "network" && len(lines) != 1 {
			t.Fatalf("failed network creation attempted cleanup of unowned resources: %s", calls)
		}
		fields := strings.Fields(lines[0])
		name := fields[len(fields)-1]
		if !strings.HasPrefix(name, "egasmoke-") || name == previous {
			t.Fatalf("smoke reused a resource name: %q", name)
		}
		previous = name
		if failAt == "run" && (len(lines) != 4 || !strings.HasPrefix(lines[1], "run ") || lines[2] != "rm -f "+name+"-r1 "+name+"-r2" || lines[3] != "network rm -f "+name) {
			t.Fatalf("partial startup did not finish owned-resource cleanup: %s", calls)
		}
	}
}

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
func (p *pki) issue(t *testing.T, cn string, serial int64, modify ...func(*x509.Certificate)) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	for _, change := range modify {
		change(tmpl)
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
	c.grace = time.Second
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	c.listen = l.Addr().String()
	l.Close()
	e := newExporter(quiet, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, &tlsSource{cfg: c, logger: discard}, e, discard) }()
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
	p, extra, dir := newPKI(t), newPKI(t), t.TempDir()
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), clientCAFile: filepath.Join(dir, "ca.crt")}
	crt, key := p.issue(t, "server-1", 2)
	write(t, cfg.certFile, []byte(strings.ReplaceAll(string(crt)+string(p.pem), "\n", "\r\n")))
	write(t, cfg.keyFile, key)
	write(t, cfg.clientCAFile, []byte(strings.ReplaceAll(string(p.pem)+string(extra.pem), "\n", "\r\n")))

	addr, stop := start(t, cfg)
	defer stop()

	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	cc, ck := p.issue(t, "scraper", 3)
	clientPair, _ := tls.X509KeyPair(cc, ck)
	if _, err := get(addr, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientPair}, MaxVersion: tls.VersionTLS12}); err == nil {
		t.Error("TLS 1.2 was accepted")
	}

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
	write(t, cfg.certFile, []byte(strings.ReplaceAll(string(crt)+string(p.pem), "\n", "\r\n")))
	write(t, cfg.keyFile, key)
	write(t, cfg.clientCAFile, []byte(strings.ReplaceAll(string(np.pem)+string(extra.pem), "\n", "\r\n")))
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

func TestMetricsRoute(t *testing.T) {
	p, dir := newPKI(t), t.TempDir()
	crt, key := p.issue(t, "server", 2)
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key")}
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	addr, stop := start(t, cfg)
	defer stop()
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	for path, want := range map[string]int{"/metrics": http.StatusOK, "/": http.StatusNotFound, "/metrics/": http.StatusNotFound} {
		resp, err := client.Get("https://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestServerBoundsIncompleteRequestBodies(t *testing.T) {
	p, dir := newPKI(t), t.TempDir()
	crt, key := p.issue(t, "server", 2)
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), timeout: time.Minute, grace: time.Second}
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	addr, stop := start(t, cfg)
	defer stop()
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	client, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Outlast the server's read budget, but not its much longer write budget.
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, client); err != nil {
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("incomplete request body outlived the server read budget")
		}
	}
}

// A scrape still running when the grace period ends is cancelled, which is what
// kills its vtysh, and run reports that it did not drain.
func TestShutdownCancelsScrapesAfterGrace(t *testing.T) {
	for _, body := range []bool{false, true} {
		name := "ordinary GET"
		if body {
			name = "incomplete request body"
		}
		t.Run(name, func(t *testing.T) { testShutdownCancelsScrapesAfterGrace(t, body) })
	}
}

func testShutdownCancelsScrapesAfterGrace(t *testing.T, body bool) {
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
		<-ctx.Done() // a hung vtysh
		if ctx.Err() != context.Canceled {
			t.Error("read ended at its own deadline instead of shutdown cancellation")
		}
		time.Sleep(300 * time.Millisecond) // taking its time to die
		close(cancelled)
		return nil, ctx.Err()
	}, 3*time.Second)
	e.cs = e.cs[:1]

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	// run owns routing as well as shutdown, so main cannot hide the exporter's
	// Wait behind a handler wrapper.
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
	// A patient client cannot hide a missing server cancellation path.
	var incomplete *tls.Conn
	if body {
		conn, err := tls.Dial("tcp", cfg.listen, &tls.Config{RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		incomplete = conn
		if _, err := io.WriteString(conn, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
	} else {
		patient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: time.Minute}
		defer patient.CloseIdleConnections()
		go func() {
			if resp, err := patient.Get("https://" + cfg.listen + "/metrics"); err == nil {
				resp.Body.Close()
			}
		}()
	}
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
	if incomplete != nil {
		incomplete.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := io.Copy(io.Discard, incomplete); err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Error("run returned without closing the incomplete request's connection")
			}
		}
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
	first, err := src.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	crt, key = p.issue(t, "two", 3)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	if again, _ := src.get(nil); again != first {
		t.Error("files were re-read inside the recheck interval")
	}
	src.checked = time.Now().Add(-cfg.recheck)
	second, err := src.get(nil)
	if err != nil || second == first || second.Certificates[0].Leaf.Subject.CommonName != "two" {
		t.Fatalf("replacement certificate was not installed after recheck: %v", err)
	}
}

func TestClientCARotationForReusedAndResumedConnections(t *testing.T) {
	p, dir := newPKI(t), t.TempDir()
	cfg := config{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), clientCAFile: filepath.Join(dir, "ca.crt")}
	crt, key := p.issue(t, "server", 2)
	write(t, cfg.certFile, crt)
	write(t, cfg.keyFile, key)
	write(t, cfg.clientCAFile, p.pem)
	addr, stop := start(t, cfg)
	defer stop()
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	cc, ck := p.issue(t, "scraper", 3)
	pair, err := tls.X509KeyPair(cc, ck)
	if err != nil {
		t.Fatal(err)
	}
	tc := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	tr := &http.Transport{TLSClientConfig: tc}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	scrape := func(client *http.Client) (tls.ConnectionState, bool, error) {
		reused := false
		trace := &httptrace.ClientTrace{GotConn: func(c httptrace.GotConnInfo) { reused = c.Reused }}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, "https://"+addr+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return tls.ConnectionState{}, reused, err
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("scrape status = %d, want 200", resp.StatusCode)
		}
		return *resp.TLS, reused, nil
	}
	if state, _, err := scrape(client); err != nil || state.DidResume {
		t.Fatalf("initial handshake: resumed=%v, err=%v", state.DidResume, err)
	}
	client.CloseIdleConnections()
	if state, reused, err := scrape(client); err != nil || reused || !state.DidResume {
		t.Fatalf("resumption baseline: reused=%v, resumed=%v, err=%v", reused, state.DidResume, err)
	}
	// Replacing the CA applies to new TLS connections, including resumption.
	write(t, cfg.clientCAFile, newPKI(t).pem)
	fresh := &http.Client{Transport: &http.Transport{TLSClientConfig: tc.Clone()}, Timeout: 5 * time.Second}
	defer fresh.CloseIdleConnections()
	if _, _, err := scrape(fresh); err == nil {
		t.Fatal("old client was accepted on a new TLS connection after CA replacement")
	}
	// Existing connections retain the authentication established at their handshake.
	if _, reused, err := scrape(client); err != nil || !reused {
		t.Fatalf("existing connection after CA replacement: reused=%v, err=%v", reused, err)
	}
}

func TestTLSCertificateFilesRejectEveryDamagedBlock(t *testing.T) {
	p, q := newPKI(t), newPKI(t)
	crt, key := p.issue(t, "server", 2)
	for _, file := range []string{"server", "client CA"} {
		first, second := string(p.pem), string(q.pem)
		if file == "server" {
			first, second = string(crt), string(p.pem)
		}
		badPEM := "-----BEGIN CERTIFICATE-----\n!invalid-base64!\n-----END CERTIFICATE-----\n"
		truncated := "-----BEGIN CERTIFICATE-----\nMIIB"
		badDER := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}))
		cases := map[string]string{
			"garbage prefix":      "garbage\n" + first,
			"garbage middle":      first + "garbage\n" + second,
			"garbage trailer":     first + "garbage\n",
			"malformed prefix":    badPEM + first,
			"malformed middle":    first + badPEM + second,
			"malformed trailer":   first + badPEM,
			"truncated prefix":    truncated + "\n" + first,
			"truncated middle":    first + truncated + "\n" + second,
			"truncated trailer":   first + truncated,
			"invalid DER prefix":  badDER + first,
			"invalid DER middle":  first + badDER + second,
			"invalid DER trailer": first + badDER,
			"empty":               "",
			"comments only":       "# not a certificate\n",
		}
		for _, eol := range []string{"\n", "\r\n"} {
			for name, bundle := range cases {
				t.Run(fmt.Sprintf("%s/%q/%s", file, eol, name), func(t *testing.T) {
					dir := t.TempDir()
					c := config{certFile: filepath.Join(dir, "cert"), keyFile: filepath.Join(dir, "key"), clientCAFile: filepath.Join(dir, "ca")}
					write(t, c.certFile, crt)
					if file == "server" {
						write(t, c.certFile, []byte(first+second))
					}
					write(t, c.keyFile, key)
					write(t, c.clientCAFile, append(append([]byte{}, p.pem...), q.pem...))
					src := &tlsSource{cfg: c, logger: discard}
					good, err := src.get(nil)
					if err != nil {
						t.Fatal(err)
					}
					path := c.clientCAFile
					if file == "server" {
						path = c.certFile
					}
					original, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					write(t, path, []byte(strings.ReplaceAll(bundle, "\n", eol)))
					if _, err := (&tlsSource{cfg: c, logger: discard}).get(nil); err == nil {
						t.Error("damaged bundle accepted at startup")
					}
					got, err := src.get(nil)
					if err != nil || got != good {
						t.Fatalf("damaged bundle replaced last-good config: err=%v", err)
					}
					if v := gauge(t, src, "frrk8s_exporter_tls_config_current"); v != 0 {
						t.Fatalf("reload health=%v, want 0", v)
					}
					write(t, path, []byte(strings.ReplaceAll(string(original), "\n", eol)))
					if v := gauge(t, src, "frrk8s_exporter_tls_config_current"); v != 1 {
						t.Fatalf("valid %q replacement did not restore reload health: %v", eol, v)
					}
				})
			}
		}
	}
}

func TestTLSClientCABundles(t *testing.T) {
	p, q := newPKI(t), newPKI(t)
	for name, bundle := range map[string]struct {
		data  string
		roots int
	}{
		"single":   {string(p.pem), 1},
		"multiple": {string(p.pem) + string(q.pem), 2},
		"comments": {" \n# first root\n\t" + string(p.pem) + "\n \t# second root, literal -----BEGIN CERTIFICATE-----\n" + string(q.pem) + "\n# end without newline", 2},
	} {
		for _, eol := range []string{"\n", "\r\n"} {
			t.Run(fmt.Sprintf("%s/%q", name, eol), func(t *testing.T) {
				pool, err := clientCAPool([]byte(strings.ReplaceAll(bundle.data, "\n", eol)))
				if err != nil {
					t.Fatal(err)
				}
				if len(pool.Subjects()) != bundle.roots {
					t.Fatalf("got %d roots, want %d", len(pool.Subjects()), bundle.roots)
				}
			})
		}
	}
}

func TestTLSServerCertificatePolicyAndRecovery(t *testing.T) {
	p := newPKI(t)
	for name, tc := range map[string]struct {
		modify func(*x509.Certificate)
		valid  bool
	}{
		"future": {func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(2 * time.Hour)
		}, false},
		"expired": {func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		}, false},
		"client only": {func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, false},
		"unknown only": {func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}, false},
		"absent usage": {func(c *x509.Certificate) { c.ExtKeyUsage = nil }, true},
		"any usage":    {func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config{certFile: filepath.Join(dir, "cert"), keyFile: filepath.Join(dir, "key")}
			cert, key := p.issue(t, "good", 2)
			write(t, cfg.certFile, cert)
			write(t, cfg.keyFile, key)
			src := &tlsSource{cfg: cfg, logger: discard}
			good, err := src.get(nil)
			if err != nil {
				t.Fatal(err)
			}
			candidate, candidateKey := p.issue(t, "candidate", 3, tc.modify)
			if _, err := build(string(candidate), string(candidateKey), "", false); (err == nil) != tc.valid {
				t.Fatalf("startup validity: error=%v, want valid=%v", err, tc.valid)
			}
			write(t, cfg.certFile, candidate)
			write(t, cfg.keyFile, candidateKey)
			got, err := src.get(nil)
			if err != nil {
				t.Fatal(err)
			}
			want := 0.0
			if tc.valid {
				want = 1
				if got == good {
					t.Error("valid replacement was not installed")
				}
			} else if got != good {
				t.Error("unusable certificate replaced last-good configuration")
			}
			if v := gauge(t, src, "frrk8s_exporter_tls_config_current"); v != want {
				t.Errorf("reload health=%v, want %v", v, want)
			}
			write(t, cfg.certFile, cert)
			write(t, cfg.keyFile, key)
			if v := gauge(t, src, "frrk8s_exporter_tls_config_current"); v != 1 {
				t.Errorf("recovery health=%v, want 1", v)
			}
		})
	}
}

func TestTLSDoesNotRequireKeyPairLeafCache(t *testing.T) {
	t.Setenv("GODEBUG", "x509keypairleaf=0")
	p := newPKI(t)
	cert, key := p.issue(t, "server", 2)
	cfg, err := build(string(cert), string(key), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Certificates[0].Leaf == nil {
		t.Fatal("parsed server leaf is missing")
	}
}

func TestTLSServesEveryValidatedCertificateBlock(t *testing.T) {
	p := newPKI(t)
	cert, key := p.issue(t, "server", 2)
	for _, eol := range []string{"\n", "\r\n"} {
		for _, withRoot := range []bool{false, true} {
			for _, gap := range []string{"", "\n\t", "\n# intermediate\n\t"} {
				t.Run(fmt.Sprintf("%q/root=%v/gap=%q", eol, withRoot, gap), func(t *testing.T) {
					bundle := gap + string(cert)
					want := 1
					if withRoot {
						bundle += gap + string(p.pem)
						want++
					}
					cfg, err := build(strings.ReplaceAll(bundle, "\n", eol), strings.ReplaceAll(string(key), "\n", eol), "", false)
					if err != nil {
						t.Fatal(err)
					}
					chain := cfg.Certificates[0].Certificate
					if len(chain) != want || (withRoot && string(chain[1]) != string(p.ca.Raw)) {
						t.Fatal("served chain does not contain every validated certificate")
					}
				})
			}
		}
	}
}
