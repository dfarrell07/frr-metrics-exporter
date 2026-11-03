// SPDX-License-Identifier: Apache-2.0

// Command frr-metrics-exporter serves Prometheus metrics for an FRR that runs
// outside Kubernetes: BGP sessions and per-family prefixes, BFD sessions and
// EVPN VNIs, read through vtysh and served over mTLS.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/dfarrell07/frr-metrics-exporter/collector"
)

// maxScrapes covers a pair of Prometheus replicas and an operator with curl;
// more get 503 instead of piling vtysh processes onto FRR.
const maxScrapes = 4

// maxResponses bounds snapshots held by clients that read slowly, while
// leaving room for new reads when the first four scrapes are writing.
const maxResponses = 2 * maxScrapes

type config struct {
	listen, certFile, keyFile, clientCAFile string
	collectors, vtysh                       string
	timeout                                 time.Duration
	// Not flags: how long shutdown waits for scrapes, and the shortest time
	// between reads of the TLS files.
	grace, recheck time.Duration
}

func parseFlags() (config, []collector.Collector, error) {
	c := config{grace: 5 * time.Second, recheck: time.Second}
	flag.StringVar(&c.listen, "listen", "127.0.0.1:9141", "address to listen on; non-loopback addresses require --tls-client-ca-file")
	flag.StringVar(&c.certFile, "tls-cert-file", "", "server certificate (PEM), re-read when it changes")
	flag.StringVar(&c.keyFile, "tls-key-file", "", "server private key (PEM)")
	flag.StringVar(&c.clientCAFile, "tls-client-ca-file", "", "CA (PEM) that client certificates must chain to; re-read when it changes")
	flag.StringVar(&c.collectors, "collectors", "bgp,bfd,evpn", "collectors to run: any of bgp, bfd, evpn")
	flag.StringVar(&c.vtysh, "vtysh", "/usr/bin/vtysh", "path to vtysh")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.DurationVar(&c.timeout, "scrape-timeout", 8*time.Second, "deadline for all FRR reads in one scrape; keep it below the scraper's timeout")
	flag.Parse()
	if *showVersion {
		fmt.Println(version())
		os.Exit(0)
	}
	cs, err := collector.Select(c.collectors)
	switch {
	case err != nil:
	case c.certFile == "" || c.keyFile == "" || flag.NArg() > 0:
		err = errors.New("--tls-cert-file and --tls-key-file are required, and no arguments are accepted")
	case c.timeout <= 0 || c.timeout > time.Duration(math.MaxInt64)-5*time.Second:
		err = errors.New("--scrape-timeout must be positive and leave room for the 5s response budget")
	default:
		err = checkListen(c)
	}
	return c, cs, err
}

func main() {
	c, cs, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("starting", "listen", c.listen, "mtls", c.clientCAFile != "", "collectors", c.collectors)

	src := &tlsSource{cfg: c, logger: logger}
	base := prometheus.NewRegistry()
	base.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), src)
	e := &exporter{run: collector.Vtysh{Path: c.vtysh}.Run, cs: cs, timeout: c.timeout, base: base,
		sem: make(chan struct{}, maxScrapes), responses: make(chan struct{}, maxResponses), logger: logger}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, src, e, logger); err != nil {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
	logger.Info("stopped")
}

// run serves /metrics until ctx is cancelled, then drains in-flight scrapes. Scrapes
// still running after the grace period are cancelled, and run waits for their
// vtysh processes to be killed before it returns, so none outlives the exporter.
func run(ctx context.Context, src *tlsSource, e *exporter, logger *slog.Logger) error {
	if _, err := src.get(nil); err != nil {
		return err
	}
	c := src.cfg
	requestCtx, cancelRequests := context.WithCancel(context.Background())
	mux := http.NewServeMux()
	mux.Handle("/metrics", e)
	srv := &http.Server{
		Addr:         c.listen,
		Handler:      mux,
		BaseContext:  func(net.Listener) context.Context { return requestCtx },
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: src.get},
		ReadTimeout:  3 * time.Second,           // includes request bodies; write deadlines cannot bound body draining
		WriteTimeout: c.timeout + 5*time.Second, // covers the scrape and the response
		IdleTimeout:  2 * time.Minute,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	defer func() {
		// Connection closure does not always cancel a handler with an unread body.
		cancelRequests()
		srv.Close()
		e.Wait()
	}()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), c.grace)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// checkListen refuses to serve beyond loopback without client certificates.
func checkListen(c config) error {
	if c.clientCAFile != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(c.listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--listen %s is not loopback: set --tls-client-ca-file, or listen on loopback behind a proxy", c.listen)
	}
	return nil
}

func version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "frr-metrics-exporter (unknown build)"
	}
	rev := "unknown"
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			rev = s.Value
		}
	}
	return fmt.Sprintf("frr-metrics-exporter %s, revision %s, %s", bi.Main.Version, rev, bi.GoVersion)
}
