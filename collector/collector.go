// SPDX-License-Identifier: Apache-2.0

// Package collector reads FRR through vtysh and turns what it finds into
// Prometheus metrics. Each Collector makes its reads, parses the JSON FRR
// returns and builds its complete result before any of it is served, so a
// failed read never leaves half a result.
//
// The series names, types and BGP labels follow the frr-k8s exporter.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "frrk8s_"

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(namespace+name, help, labels, nil)
}

// A Runner runs one read-only vtysh command and returns its standard output.
type Runner func(ctx context.Context, command string) ([]byte, error)

// A Collector reads FRR and returns its complete set of metrics, or an error
// and none.
type Collector struct {
	Name    string
	Collect func(context.Context, Runner) ([]prometheus.Metric, error)
}

var all = []Collector{
	{"bgp", collectBGP},
	{"bfd", collectBFD},
	{"evpn", collectEVPN},
}

// Select resolves a comma-separated list such as "bgp,evpn".
func Select(list string) ([]Collector, error) {
	var out []Collector
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		i := slices.IndexFunc(all, func(c Collector) bool { return c.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("unknown collector %q", name)
		}
		if slices.ContainsFunc(out, func(c Collector) bool { return c.Name == name }) {
			return nil, fmt.Errorf("collector %q listed twice", name)
		}
		out = append(out, all[i])
	}
	return out, nil
}

var (
	successDesc  = desc("scrape_collector_success", "1 if the collector read and parsed FRR completely, 0 if it emitted nothing", "collector")
	durationDesc = desc("scrape_collector_duration_seconds", "Time the collector spent reading FRR", "collector")
)

// Gather runs the collectors at once, so a slow one cannot use up the others'
// time, and appends each one's status series.
func Gather(ctx context.Context, run Runner, cs []Collector, logger *slog.Logger) []prometheus.Metric {
	results := make([][]prometheus.Metric, len(cs))
	var wg sync.WaitGroup
	for i, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = collectOne(ctx, run, c, logger)
		}()
	}
	wg.Wait()
	return slices.Concat(results...)
}

func collectOne(ctx context.Context, run Runner, c Collector, logger *slog.Logger) []prometheus.Metric {
	start := time.Now()
	ms, err := c.Collect(ctx, run)
	if err == nil {
		err = ctx.Err() // Parsing can finish after the read's context was cancelled.
	}
	success := 1.0
	if err != nil {
		success, ms = 0, nil
		if errors.Is(err, context.Canceled) { // the scraper went away
			logger.Debug("collector cancelled", "collector", c.Name)
		} else {
			logger.Error("collector failed", "collector", c.Name, "error", err)
		}
	}
	return append(ms,
		prometheus.MustNewConstMetric(successDesc, prometheus.GaugeValue, success, c.Name),
		prometheus.MustNewConstMetric(durationDesc, prometheus.GaugeValue, time.Since(start).Seconds(), c.Name))
}

// Snapshot is a finished set of metrics served as one prometheus.Collector.
// Its Describe is empty, which makes it an unchecked collector.
type Snapshot []prometheus.Metric

func (Snapshot) Describe(chan<- *prometheus.Desc) {}
func (s Snapshot) Collect(ch chan<- prometheus.Metric) {
	for _, m := range s {
		ch <- m
	}
}
