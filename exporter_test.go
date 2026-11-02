// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dfarrell07/frr-metrics-exporter/collector"
)

var cs = func() []collector.Collector {
	cs, err := collector.Select("bgp,bfd,evpn")
	if err != nil {
		panic(err)
	}
	return cs
}()

func newExporter(run collector.Runner, timeout time.Duration) *exporter {
	return &exporter{run: run, cs: cs, timeout: timeout, base: prometheus.NewRegistry(),
		sem: make(chan struct{}, maxScrapes), responses: make(chan struct{}, maxResponses), logger: discard}
}

func TestScrapeDeadline(t *testing.T) {
	// A hung FRR must not hang the scrape: the deadline reaches every read.
	hung := func(ctx context.Context, _ string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	srv := httptest.NewServer(newExporter(hung, 100*time.Millisecond))
	defer srv.Close()
	start := time.Now()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || time.Since(start) > 2*time.Second {
		t.Errorf("status %d after %v", resp.StatusCode, time.Since(start))
	}
	for _, c := range cs {
		if want := fmt.Sprintf(`frrk8s_scrape_collector_success{collector=%q} 0`, c.Name); !strings.Contains(string(body), want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
}

func TestScrapeLimit(t *testing.T) {
	var started sync.WaitGroup
	started.Add(maxScrapes)
	release := make(chan struct{})
	e := newExporter(func(ctx context.Context, _ string) ([]byte, error) {
		started.Done()
		select {
		case <-release:
		case <-ctx.Done():
		}
		return []byte("{}"), nil
	}, 10*time.Second)
	e.cs = e.cs[:1] // one read per scrape
	srv := httptest.NewServer(e)
	defer srv.Close()
	var done sync.WaitGroup
	for i := 0; i < maxScrapes; i++ {
		done.Add(1)
		go func() { defer done.Done(); http.Get(srv.URL) }()
	}
	started.Wait()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("scrape beyond the limit: status %d, want 503", resp.StatusCode)
	}
	close(release)
	done.Wait()
}

const bgpCmd = "show bgp vrf all neighbors json"

// quiet answers every read with empty but valid output, as a real vtysh
// would, and fails once the deadline has passed.
func quiet(ctx context.Context, command string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.Contains(command, "bfd") || command == "show evpn es detail json" {
		return []byte("[]"), nil
	}
	return []byte("{}"), nil
}

func scrapeBody(t *testing.T, e *exporter, header ...string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestSlowCollectorDoesNotStarveTheOthers(t *testing.T) {
	// BGP hangs until the deadline; BFD and EVPN must still get their full time.
	run := func(ctx context.Context, command string) ([]byte, error) {
		if command == bgpCmd {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return quiet(ctx, command)
	}
	_, body := scrapeBody(t, newExporter(run, 200*time.Millisecond))
	for collector, want := range map[string]string{"bgp": "0", "bfd": "1", "evpn": "1"} {
		if line := fmt.Sprintf(`frrk8s_scrape_collector_success{collector=%q} %s`, collector, want); !strings.Contains(body, line) {
			t.Errorf("missing %q", line)
		}
	}
}

func TestScrapeSlotIsFreeWhileTheResponseIsWritten(t *testing.T) {
	// A client that reads slowly must not keep FRR scrapes from other clients.
	e := newExporter(quiet, time.Second)
	release := make(chan struct{})
	var writing sync.WaitGroup
	for i := 0; i < maxScrapes; i++ {
		writing.Add(1)
		w := &stuckWriter{entered: writing.Done, release: release}
		go e.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	}
	writing.Wait() // every slot's scrape is now stuck writing its response
	if code, _ := scrapeBody(t, e); code != 200 {
		t.Errorf("a scrape while others write got %d, want 200", code)
	}
	close(release)
}

func TestSlowResponsesHaveASharedLimitAndRecover(t *testing.T) {
	var reads atomic.Int32
	e := newExporter(func(ctx context.Context, command string) ([]byte, error) {
		reads.Add(1)
		return quiet(ctx, command)
	}, time.Second)
	e.cs = e.cs[:1] // one FRR read for each admitted response
	release := make(chan struct{})
	var once sync.Once
	var done sync.WaitGroup
	releaseAll := func() { once.Do(func() { close(release) }); done.Wait() }
	defer releaseAll()
	for range maxResponses {
		entered := make(chan struct{})
		w := &stuckWriter{entered: func() { close(entered) }, release: release}
		done.Add(1)
		go func() { defer done.Done(); e.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil)) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("response never reached writer")
		}
	}
	if reads.Load() != int32(maxResponses) {
		t.Fatalf("got %d admitted reads, want %d", reads.Load(), maxResponses)
	}
	before := reads.Load()
	if code, _ := scrapeBody(t, e); code != http.StatusServiceUnavailable {
		t.Errorf("response beyond limit: status %d, want 503", code)
	}
	if reads.Load() != before {
		t.Error("rejected response invoked FRR")
	}
	releaseAll()
	if code, _ := scrapeBody(t, e); code != http.StatusOK {
		t.Errorf("after responses drain: status %d, want 200", code)
	}
}

type stuckWriter struct {
	entered func()
	release chan struct{}
	once    sync.Once
}

func (w *stuckWriter) Header() http.Header { return http.Header{} }

func (w *stuckWriter) WriteHeader(int) {}

func (w *stuckWriter) Write(p []byte) (int, error) {
	w.once.Do(w.entered)
	<-w.release
	return len(p), nil
}

func TestScraperTimeoutLowersTheDeadline(t *testing.T) {
	var remaining time.Duration
	var mu sync.Mutex
	run := func(ctx context.Context, command string) ([]byte, error) {
		d, _ := ctx.Deadline()
		mu.Lock()
		remaining = time.Until(d)
		mu.Unlock()
		return quiet(ctx, command)
	}
	e := newExporter(run, time.Minute)
	scrapeBody(t, e, "X-Prometheus-Scrape-Timeout-Seconds", "2")
	mu.Lock()
	if remaining > 1800*time.Millisecond || remaining < time.Second {
		t.Errorf("with a 2s scraper timeout the deadline was %v away, want about 1.8s", remaining)
	}
	mu.Unlock()
	scrapeBody(t, e, "X-Prometheus-Scrape-Timeout-Seconds", "junk")
	mu.Lock()
	if remaining < 50*time.Second {
		t.Errorf("an unparseable header changed the deadline to %v", remaining)
	}
	mu.Unlock()
}

func TestInvalidOrLargeScraperTimeoutKeepsTheBudget(t *testing.T) {
	e := newExporter(quiet, time.Minute)
	for _, header := range []string{"", "junk", "0", "-1", "NaN", "+Inf", "1e30", "120"} {
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", header)
		if got := e.deadline(r); got != e.timeout {
			t.Errorf("header %q: deadline = %v, want %v", header, got, e.timeout)
		}
	}
}

func TestInconsistentOutputFailsTheScrape(t *testing.T) {
	m := prometheus.MustNewConstMetric(prometheus.NewDesc("frrk8s_test_series", "x", []string{"l"}, nil), prometheus.GaugeValue, 1, "v")
	e := newExporter(quiet, time.Second)
	e.cs = []collector.Collector{{Name: "dup", Collect: func(context.Context, collector.Runner) ([]prometheus.Metric, error) {
		return []prometheus.Metric{m, m}, nil // the same series twice
	}}}
	if code, _ := scrapeBody(t, e); code != http.StatusInternalServerError {
		t.Errorf("duplicate series: status %d, want 500 rather than a silent subset", code)
	}
}
