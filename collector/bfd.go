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
		get  func(*bfdCounterRow) *uint64
	}{
		{desc("bfd_control_packet_input", "Number of received BFD control packets", bfdLabels...), func(r *bfdCounterRow) *uint64 { return r.ControlIn }},
		{desc("bfd_control_packet_output", "Number of sent BFD control packets", bfdLabels...), func(r *bfdCounterRow) *uint64 { return r.ControlOut }},
		{desc("bfd_echo_packet_input", "Number of received BFD echo packets", bfdLabels...), func(r *bfdCounterRow) *uint64 { return r.EchoIn }},
		{desc("bfd_echo_packet_output", "Number of sent BFD echo packets", bfdLabels...), func(r *bfdCounterRow) *uint64 { return r.EchoOut }},
		{desc("bfd_session_up_events", "Number of BFD session up events", bfdLabels...), func(r *bfdCounterRow) *uint64 { return r.UpEvents }},
		{desc("bfd_session_down_events", "Number of BFD session down events", bfdLabels...), func(r *bfdCounterRow) *uint64 { return r.DownEvents }},
		{desc("bfd_zebra_notifications", "Number of BFD zebra notifications", bfdLabels...), func(r *bfdCounterRow) *uint64 { return r.ZebraNotifications }},
	}
)

// bfdKey is FRR's session identity as both replies carry it. interface is
// absent on a multihop session.
type bfdKey struct {
	Peer      string `json:"peer"`
	VRF       string `json:"vrf"`
	Local     string `json:"local"`
	Interface string `json:"interface"`
	Multihop  *bool  `json:"multihop"`
	ID        uint32 `json:"id"` // correlation only, never a time-series label
}

func (k bfdKey) valid() bool {
	// FRR may omit local, interface and VRF; never invent those values.
	return k.ID != 0 && k.Peer != "" && k.Multihop != nil
}

func (k bfdKey) labels() [5]string {
	return [5]string{k.Peer, k.VRF, k.Local, k.Interface, strconv.FormatBool(*k.Multihop)}
}

type bfdSessionRow struct {
	bfdKey
	Status string          `json:"status"`
	Name   json.RawMessage `json:"bfd-name"` // present for nonordinary modes; never merge their identities
}

// The counters are pointers: a field FRR does not report is omitted, not 0.
type bfdCounterRow struct {
	bfdKey
	ControlIn          *uint64 `json:"control-packet-input"`
	ControlOut         *uint64 `json:"control-packet-output"`
	EchoIn             *uint64 `json:"echo-packet-input"`
	EchoOut            *uint64 `json:"echo-packet-output"`
	UpEvents           *uint64 `json:"session-up"`
	DownEvents         *uint64 `json:"session-down"`
	ZebraNotifications *uint64 `json:"zebra-notifications"`
}

// collectBFD reads every session in every VRF with two commands and joins them
// on session ID, cross-checking the full label identity. A session present in
// only one reply changed between reads; discard the whole result so success
// never describes an incomplete snapshot. Duplicate IDs or label identities
// also fail rather than silently mixing sessions.
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
	if sessions == nil || counters == nil {
		return nil, fmt.Errorf("BFD peers and counters must be arrays, not null")
	}
	byID := make(map[uint32]*bfdCounterRow, len(counters))
	keys := make(map[[5]string]bool, len(counters))
	for i := range counters {
		c := &counters[i]
		if !c.valid() {
			return nil, fmt.Errorf("BFD counter row has no ID, peer or multihop flag: %+v", c.bfdKey)
		}
		if byID[c.ID] != nil || keys[c.labels()] {
			return nil, fmt.Errorf("duplicate BFD counter ID or identity: %+v", c.bfdKey)
		}
		byID[c.ID], keys[c.labels()] = c, true
	}
	var ms []prometheus.Metric
	for _, s := range sessions {
		if len(s.Name) != 0 {
			return nil, fmt.Errorf("BFD session %d uses unsupported named/SBFD mode", s.ID)
		}
		if !s.valid() || s.Status == "" {
			return nil, fmt.Errorf("BFD session has no ID, peer, multihop flag or status: %+v", s.bfdKey)
		}
		l := s.labels()
		c := byID[s.ID]
		if c == nil || c.labels() != l {
			return nil, fmt.Errorf("BFD session %d has no matching counters and identity", s.ID)
		}
		delete(byID, s.ID)
		up := 0.0
		if s.Status == "up" {
			up = 1
		}
		ms = append(ms, prometheus.MustNewConstMetric(bfdSessionUp, prometheus.GaugeValue, up, l[:]...))
		for _, m := range bfdCounters {
			if v := m.get(c); v != nil {
				ms = append(ms, prometheus.MustNewConstMetric(m.desc, prometheus.CounterValue, float64(*v), l[:]...))
			}
		}
	}
	if len(byID) != 0 {
		return nil, fmt.Errorf("BFD counters contain %d sessions absent from the peers read", len(byID))
	}
	return ms, nil
}
