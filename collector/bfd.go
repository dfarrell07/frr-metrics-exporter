// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// BFD series keep frr-k8s's names and add the rest of FRR's session identity
// (local address, interface, single or multihop), so two sessions to one peer
// never collide. peer and vrf keep their meaning, except that for an unnumbered
// BGP peer the BGP series carry the interface name as peer and these carry the
// address, with the interface in its own label.
var (
	bfdLabels = []string{"peer", "vrf", "local", "interface", "multihop"}

	bfdSessionUp = desc("bfd_session_up", "BFD session state (1 is up, 0 is down)", bfdLabels...)
	bfdCounters  = []struct {
		desc *prometheus.Desc
		get  func(*bfdCounterRow) *int64
	}{
		{desc("bfd_control_packet_input", "Number of received BFD control packets", bfdLabels...), func(r *bfdCounterRow) *int64 { return r.ControlIn }},
		{desc("bfd_control_packet_output", "Number of sent BFD control packets", bfdLabels...), func(r *bfdCounterRow) *int64 { return r.ControlOut }},
		{desc("bfd_echo_packet_input", "Number of received BFD echo packets", bfdLabels...), func(r *bfdCounterRow) *int64 { return r.EchoIn }},
		{desc("bfd_echo_packet_output", "Number of sent BFD echo packets", bfdLabels...), func(r *bfdCounterRow) *int64 { return r.EchoOut }},
		{desc("bfd_session_up_events", "Number of BFD session up events", bfdLabels...), func(r *bfdCounterRow) *int64 { return r.UpEvents }},
		{desc("bfd_session_down_events", "Number of BFD session down events", bfdLabels...), func(r *bfdCounterRow) *int64 { return r.DownEvents }},
		{desc("bfd_zebra_notifications", "Number of BFD zebra notifications", bfdLabels...), func(r *bfdCounterRow) *int64 { return r.ZebraNotifications }},
	}
)

// bfdKey is FRR's session identity as both replies carry it. interface is
// absent on a multihop session.
type bfdKey struct {
	Peer      string `json:"peer"`
	VRF       string `json:"vrf"`
	Local     string `json:"local"`
	Interface string `json:"interface"`
	Multihop  bool   `json:"multihop"`
}

func (k bfdKey) labels() []string {
	return []string{k.Peer, k.VRF, k.Local, k.Interface, strconv.FormatBool(k.Multihop)}
}

type bfdSessionRow struct {
	bfdKey
	Status string `json:"status"`
}

// The counters are pointers: a field FRR does not report is omitted, not 0.
type bfdCounterRow struct {
	bfdKey
	ControlIn          *int64 `json:"control-packet-input"`
	ControlOut         *int64 `json:"control-packet-output"`
	EchoIn             *int64 `json:"echo-packet-input"`
	EchoOut            *int64 `json:"echo-packet-output"`
	UpEvents           *int64 `json:"session-up"`
	DownEvents         *int64 `json:"session-down"`
	ZebraNotifications *int64 `json:"zebra-notifications"`
}

// collectBFD reads every session in every VRF with two commands and joins them
// on the session identity. Both replies come from one FRR function, so the
// identities agree. A session in only one reply changed between the reads; its
// counters (or it) are left out until the next scrape. Two sessions with one
// identity make the data unrepresentable, so the collector fails.
func collectBFD(ctx context.Context, run Runner) ([]prometheus.Metric, error) {
	var sessions []bfdSessionRow
	var counters []bfdCounterRow
	for _, read := range []struct {
		command string
		into    any
	}{{"show bfd peers json", &sessions}, {"show bfd peers counters json", &counters}} {
		out, err := run(ctx, read.command)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(out, read.into); err != nil {
			return nil, fmt.Errorf("parsing %q: %w", read.command, err)
		}
	}
	byKey := make(map[bfdKey]*bfdCounterRow, len(counters))
	for i := range counters {
		if _, dup := byKey[counters[i].bfdKey]; dup {
			return nil, fmt.Errorf("two BFD counter rows share the identity %+v", counters[i].bfdKey)
		}
		byKey[counters[i].bfdKey] = &counters[i]
	}
	seen := make(map[bfdKey]bool, len(sessions))
	var ms []prometheus.Metric
	for _, s := range sessions {
		if seen[s.bfdKey] {
			return nil, fmt.Errorf("two BFD sessions share the identity %+v", s.bfdKey)
		}
		seen[s.bfdKey] = true
		if s.Status == "" {
			return nil, fmt.Errorf("BFD session %+v has no status", s.bfdKey)
		}
		up := 0.0
		if s.Status == "up" {
			up = 1
		}
		l := s.labels()
		ms = append(ms, prometheus.MustNewConstMetric(bfdSessionUp, prometheus.GaugeValue, up, l...))
		c, ok := byKey[s.bfdKey]
		if !ok {
			continue
		}
		for _, m := range bfdCounters {
			if v := m.get(c); v != nil {
				ms = append(ms, prometheus.MustNewConstMetric(m.desc, prometheus.CounterValue, float64(*v), l...))
			}
		}
	}
	return ms, nil
}
