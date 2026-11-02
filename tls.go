// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	tlsCurrentDesc  = prometheus.NewDesc("frrk8s_exporter_tls_config_current", "1 if the TLS key pair and client CA being served match the files on disk, 0 if the last reload failed and the previous ones are still served", nil, nil)
	tlsNotAfterDesc = prometheus.NewDesc("frrk8s_exporter_tls_cert_not_after_timestamp_seconds", "Expiry of the server certificate being served", nil, nil)
)

// tlsSource builds the server's TLS configuration from the key pair and the
// optional client CA. It re-reads the files at most once per cfg.recheck and
// rebuilds only when their contents change, so certificate and CA rotation
// need no restart. A bad rotation keeps the last good configuration, so a
// half-written file cannot take the endpoint down; frrk8s_exporter_tls_config_current
// goes to 0 and the error is logged once, not on every handshake.
type tlsSource struct {
	cfg    config
	logger *slog.Logger

	mu       sync.Mutex
	checked  time.Time
	contents [3]string
	built    *tls.Config
	notAfter time.Time
	lastErr  string // the reload error already logged; empty when current
}

func (s *tlsSource) get(*tls.ClientHelloInfo) (*tls.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refresh()
}

func (s *tlsSource) refresh() (*tls.Config, error) {
	if s.built != nil && time.Since(s.checked) < s.cfg.recheck {
		return s.built, nil
	}
	s.checked = time.Now()
	cert, key, ca, err := s.read()
	if err == nil && s.built != nil && s.contents == [3]string{cert, key, ca} {
		s.note(nil)
		return s.built, nil
	}
	if err == nil {
		var built *tls.Config
		if built, err = build(cert, key, ca, s.cfg.clientCAFile != ""); err == nil {
			s.built, s.contents, s.notAfter = built, [3]string{cert, key, ca}, built.Certificates[0].Leaf.NotAfter
			s.note(nil)
			return built, nil
		}
	}
	if s.built == nil {
		return nil, err
	}
	s.note(err)
	return s.built, nil
}

// note logs a change in reload health: the first failure, and the recovery.
func (s *tlsSource) note(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg == s.lastErr {
		return
	}
	if err != nil {
		s.logger.Error("TLS reload failed; serving the previous configuration", "error", err)
	} else {
		s.logger.Info("TLS configuration reloaded")
	}
	s.lastErr = msg
}

func (s *tlsSource) read() (cert, key, ca string, err error) {
	files := []struct {
		path string
		out  *string
	}{{s.cfg.certFile, &cert}, {s.cfg.keyFile, &key}, {s.cfg.clientCAFile, &ca}}
	for _, f := range files {
		if f.path == "" {
			continue
		}
		b, rerr := os.ReadFile(f.path)
		if rerr != nil {
			return "", "", "", rerr
		}
		*f.out = string(b)
	}
	return cert, key, ca, nil
}

func build(cert, key, ca string, requireClientCert bool) (*tls.Config, error) {
	chain, err := certificatePEM([]byte(cert))
	if err != nil {
		return nil, err
	}
	// Serve exactly the chain validated above; X509KeyPair skips some raw PEM blocks.
	var normalized bytes.Buffer
	for _, cert := range chain {
		pem.Encode(&normalized, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	pair, err := tls.X509KeyPair(normalized.Bytes(), []byte(key))
	if err != nil {
		return nil, err
	}
	pair.Leaf = chain[0]
	leaf, now := pair.Leaf, time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("server certificate is outside its validity window")
	}
	if (len(leaf.ExtKeyUsage) != 0 || len(leaf.UnknownExtKeyUsage) != 0) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("server certificate does not permit server authentication")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	if requireClientCert {
		// An emptied or invalid CA file must not mean "no client authentication".
		cfg.ClientCAs, err = clientCAPool([]byte(ca))
		if err != nil {
			return nil, err
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func clientCAPool(data []byte) (*x509.CertPool, error) {
	certs, err := certificatePEM(data)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}

// certificatePEM accepts certificate PEM blocks separated by whitespace or # comments.
// Decode normally skips damaged blocks. Bound it at the next BEGIN line so every
// block in a rotation must parse before any part of the new bundle is trusted.
func certificatePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		data = bytes.TrimSpace(data)
		if len(data) == 0 {
			break
		}
		if data[0] == '#' {
			_, data, _ = bytes.Cut(data, []byte("\n"))
			continue
		}
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, errors.New("invalid data in certificate PEM")
		}
		chunk := data
		if next := bytes.Index(data[1:], []byte("\n-----BEGIN ")); next >= 0 {
			chunk = data[:next+1]
		}
		block, rest := pem.Decode(chunk)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		data = data[len(chunk)-len(rest):]
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates in PEM")
	}
	return certs, nil
}

// Describe and Collect report the reload health above on the exporter's own endpoint.
func (s *tlsSource) Describe(ch chan<- *prometheus.Desc) { ch <- tlsCurrentDesc; ch <- tlsNotAfterDesc }

func (s *tlsSource) Collect(ch chan<- prometheus.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh() //nolint:errcheck // an error leaves the previous configuration, reported below
	current := 1.0
	if s.lastErr != "" {
		current = 0
	}
	ch <- prometheus.MustNewConstMetric(tlsCurrentDesc, prometheus.GaugeValue, current)
	ch <- prometheus.MustNewConstMetric(tlsNotAfterDesc, prometheus.GaugeValue, float64(s.notAfter.Unix()))
}
