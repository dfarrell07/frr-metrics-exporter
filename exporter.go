// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dfarrell07/frr-metrics-exporter/collector"
)

// exporter answers each scrape with a fresh read of FRR bounded by one
// deadline. A scrape holds one of a few slots only while it reads FRR, never
// while the response is written, and scrapes beyond the slots get 503.
type exporter struct {
	run     collector.Runner
	cs      []collector.Collector
	timeout time.Duration // upper bound; the scraper's own timeout can lower it
	base    prometheus.Gatherer
	sem     chan struct{}
	logger  *slog.Logger
}

func (e *exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ms, ok := e.scrape(r)
	if !ok {
		http.Error(w, "too many concurrent scrapes", http.StatusServiceUnavailable)
		return
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector.Snapshot(ms))
	// A gather error means the exporter built inconsistent output (such as a
	// duplicate series). Fail the scrape rather than serve a silent subset.
	promhttp.HandlerFor(prometheus.Gatherers{e.base, reg}, promhttp.HandlerOpts{
		ErrorLog:      slog.NewLogLogger(e.logger.Handler(), slog.LevelError),
		ErrorHandling: promhttp.HTTPErrorOnError,
	}).ServeHTTP(w, r)
}

func (e *exporter) scrape(r *http.Request) ([]prometheus.Metric, bool) {
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	default:
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), e.deadline(r))
	defer cancel()
	return collector.Gather(ctx, e.run, e.cs, e.logger), true
}

// deadline is the configured timeout, lowered to 90% of the scraper's own when
// it announces one, so the answer arrives before the scraper gives up.
func (e *exporter) deadline(r *http.Request) time.Duration {
	d := e.timeout
	if s, err := strconv.ParseFloat(r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"), 64); err == nil && s > 0 {
		d = min(d, time.Duration(0.9*s*float64(time.Second)))
	}
	return d
}

// Wait returns once no scrape is reading FRR. It holds every slot, so it is for
// shutdown only.
func (e *exporter) Wait() {
	for range cap(e.sem) {
		e.sem <- struct{}{}
	}
}
