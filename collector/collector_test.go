// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

var discard = slog.New(slog.DiscardHandler)

// fake serves canned vtysh output by command. A value starting with "@" is a

// file in testdata; a missing command is an error.

func fake(replies map[string]string) Runner {
	return func(ctx context.Context, command string) ([]byte, error) {
		if err := ctx.Err(); err != nil { // like a real vtysh, which cannot start once the deadline has passed
			return nil, err
		}
		r, ok := replies[command]
		if !ok {
			return nil, fmt.Errorf("unexpected command %q", command)
		}
		if name, isFile := strings.CutPrefix(r, "@"); isFile {
			return os.ReadFile(filepath.Join("testdata", name))
		}
		return []byte(r), nil
	}
}

// series gathers ms through a pedantic registry, which also proves no two

// metrics share a name and label set, and returns `name{labels}` -> value.

func series(t *testing.T, ms []prometheus.Metric) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(Snapshot(ms))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering: %v", err)
	}
	out := map[string]float64{}
	for _, f := range families {
		for _, m := range f.Metric {
			var ls []string
			for _, l := range m.Label {
				ls = append(ls, fmt.Sprintf("%s=%q", l.GetName(), l.GetValue()))
			}
			v := m.GetGauge().GetValue() + m.GetCounter().GetValue()
			out[f.GetName()+"{"+strings.Join(ls, ",")+"}"] = v
		}
	}
	return out
}

func expect(t *testing.T, got, want map[string]float64) {
	t.Helper()
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %v (present %v), want %v", k, g, ok, v)
		}
	}
}

func absent(t *testing.T, got map[string]float64, prefixes ...string) {
	t.Helper()
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, p := range prefixes {
			if strings.HasPrefix(k, p) {
				t.Errorf("unexpected series %s", k)
			}
		}
	}
}

const bgpCmd = "show bgp vrf all neighbors json"

func TestBGPFromRealFRR(t *testing.T) {
	ms, err := collectBGP(context.Background(), fake(map[string]string{bgpCmd: "@bgp_neighbors.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	const p = `{peer="10.78.0.3",vrf="default"}`
	expect(t, got, map[string]float64{
		"frrk8s_bgp_session_up" + p:               1,
		"frrk8s_bgp_announced_prefixes_total" + p: 4, // 1 IPv4 + 3 EVPN
		"frrk8s_bgp_received_prefixes_total" + p:  2,
		"frrk8s_bgp_opens_sent" + p:               2,
		"frrk8s_bgp_total_received" + p:           8,
		"frrk8s_bgp_updates_total" + p:            6,
		`frrk8s_bgp_family_received_prefixes{afi="ipv4",peer="10.78.0.3",safi="unicast",vrf="default"}`:  1,
		`frrk8s_bgp_family_received_prefixes{afi="l2vpn",peer="10.78.0.3",safi="evpn",vrf="default"}`:    1,
		`frrk8s_bgp_family_announced_prefixes{afi="ipv4",peer="10.78.0.3",safi="unicast",vrf="default"}`: 1,
		`frrk8s_bgp_family_announced_prefixes{afi="l2vpn",peer="10.78.0.3",safi="evpn",vrf="default"}`:   3,
	})
	// The VRF without peers contributes nothing.
	absent(t, got, `frrk8s_bgp_session_up{peer="vrf`)
	for k := range got {
		if strings.Contains(k, `vrf="red"`) {
			t.Errorf("series for a VRF without peers: %s", k)
		}
	}
}

func TestBGPFamilies(t *testing.T) {
	reply := `{
	  "default": {"vrfId": 0, "vrfName": "default",
	    "192.0.2.1": {"bgpState": "Established", "messageStats": {"totalSent": 5},
	      "addressFamilyInfo": {
	        "ipv4Unicast": {"acceptedPrefixCounter": 2},
	        "ipv4Flowspec": {"acceptedPrefixCounter": 4, "sentPrefixCounter": 1}}},
	    "192.0.2.2": {"bgpState": "Established",
	      "addressFamilyInfo": {"l2VpnEvpn": {"acceptedPrefixCounter": 7, "sentPrefixCounter": 5}}},
	    "192.0.2.3": {"bgpState": "Active"}}}`
	ms, err := collectBGP(context.Background(), fake(map[string]string{bgpCmd: reply}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		// No sentPrefixCounter: the new announced gauge is omitted, received is kept.
		`frrk8s_bgp_family_received_prefixes{afi="ipv4",peer="192.0.2.1",safi="unicast",vrf="default"}`: 2,
		// An unknown family counts in the totals only, so the totals include it.
		`frrk8s_bgp_received_prefixes_total{peer="192.0.2.1",vrf="default"}`:  6,
		`frrk8s_bgp_announced_prefixes_total{peer="192.0.2.1",vrf="default"}`: 1,
		// An EVPN-only peer: the totals equal its EVPN counts.
		`frrk8s_bgp_received_prefixes_total{peer="192.0.2.2",vrf="default"}`:  7,
		`frrk8s_bgp_announced_prefixes_total{peer="192.0.2.2",vrf="default"}`: 5,
		`frrk8s_bgp_session_up{peer="192.0.2.3",vrf="default"}`:               0,
	})
	absent(t, got,
		`frrk8s_bgp_family_announced_prefixes{afi="ipv4",peer="192.0.2.1"`,
		`frrk8s_bgp_family_received_prefixes{afi="ipv4",peer="192.0.2.1",safi="flowspec"`,
		`frrk8s_bgp_family_received_prefixes{afi="ipv4",peer="192.0.2.3"`,
		// A message counter FRR did not report is absent, not zero.
		`frrk8s_bgp_opens_sent{peer="192.0.2.1"`)
}

func TestBGPPeersInVRFsAndDownPeersFromRealFRR(t *testing.T) {
	// Real FRR output: an unnumbered peer (keyed by interface), an IPv4 and an
	// IPv6 peer in the default VRF, and a peer in VRF red, none established.
	// FRR reports acceptedPrefixCounter 0 and no sentPrefixCounter for them.
	ms, err := collectBGP(context.Background(), fake(map[string]string{bgpCmd: "@bgp_neighbors_down.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		`frrk8s_bgp_session_up{peer="eth0",vrf="default"}`:                                           0,
		`frrk8s_bgp_session_up{peer="10.79.0.50",vrf="default"}`:                                     0,
		`frrk8s_bgp_session_up{peer="fd00::5",vrf="default"}`:                                        0,
		`frrk8s_bgp_session_up{peer="10.79.0.60",vrf="red"}`:                                         0,
		`frrk8s_bgp_family_received_prefixes{afi="ipv4",peer="10.79.0.60",safi="unicast",vrf="red"}`: 0,
		`frrk8s_bgp_announced_prefixes_total{peer="10.79.0.60",vrf="red"}`:                           0,
	})
	absent(t, got, "frrk8s_bgp_family_announced_prefixes")
}

func TestMalformedReadsEmitNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		c       Collector
		replies map[string]string
	}{
		"bgp not json":      {all[0], map[string]string{bgpCmd: "not json"}},
		"bgp wrong type":    {all[0], map[string]string{bgpCmd: `{"default":{"192.0.2.1":{"messageStats":"x"}}}`}},
		"bfd not json":      {all[1], map[string]string{"show bfd peers json": "[", "show bfd peers counters json": "[]"}},
		"bfd command fails": {all[1], map[string]string{"show bfd peers json": "[]"}},
		"evpn not json":     {all[2], map[string]string{"show evpn vni json": "<html>"}},
		"evpn wrong shape":  {all[2], map[string]string{"show evpn vni json": "[1]"}},
	} {
		ms := Gather(context.Background(), fake(tc.replies), []Collector{tc.c}, discard)
		got := series(t, ms)
		key := fmt.Sprintf(`frrk8s_scrape_collector_success{collector=%q}`, tc.c.Name)
		if v, ok := got[key]; !ok || v != 0 {
			t.Errorf("%s: %s = %v (present %v), want 0", name, key, v, ok)
		}
		for k := range got {
			if !strings.HasPrefix(k, "frrk8s_scrape_collector_") {
				t.Errorf("%s: failed collector emitted %s", name, k)
			}
		}
	}
}

func TestBFDFromRealFRR(t *testing.T) {
	ms, err := collectBFD(context.Background(), fake(map[string]string{
		"show bfd peers json": "@bfd_peers.json", "show bfd peers counters json": "@bfd_counters.json"}))
	if err != nil {
		t.Fatal(err)
	}
	const id = `{interface="eth0",local="10.78.0.2",multihop="false",peer="10.78.0.3",vrf="default"}`
	expect(t, series(t, ms), map[string]float64{
		"frrk8s_bfd_session_up" + id:           1,
		"frrk8s_bfd_control_packet_input" + id: 107,
		"frrk8s_bfd_session_up_events" + id:    1,
		"frrk8s_bfd_zebra_notifications" + id:  2,
	})
}

const (
	peersCmd    = "show bfd peers json"
	countersCmd = "show bfd peers counters json"
)

func TestBFDSessionsToOnePeerStayDistinct(t *testing.T) {
	// One established single-hop and two down multihop sessions to one peer in
	// one VRF: with only peer and vrf as labels these collided.
	peers := `[
	 {"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","interface":"eth0","multihop":false,"status":"up"},
	 {"peer":"192.0.2.1","vrf":"default","local":"192.0.2.11","multihop":true,"status":"down"},
	 {"peer":"192.0.2.1","vrf":"default","local":"192.0.2.12","multihop":true,"status":"down"}]`
	counters := `[
	 {"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","interface":"eth0","multihop":false,"control-packet-input":9},
	 {"peer":"192.0.2.1","vrf":"default","local":"192.0.2.11","multihop":true,"control-packet-input":0},
	 {"peer":"192.0.2.1","vrf":"default","local":"192.0.2.12","multihop":true,"control-packet-input":0}]`
	ms, err := collectBFD(context.Background(), fake(map[string]string{peersCmd: peers, countersCmd: counters}))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, series(t, ms), map[string]float64{
		`frrk8s_bfd_session_up{interface="eth0",local="192.0.2.10",multihop="false",peer="192.0.2.1",vrf="default"}`: 1,
		`frrk8s_bfd_session_up{interface="",local="192.0.2.11",multihop="true",peer="192.0.2.1",vrf="default"}`:      0,
		`frrk8s_bfd_session_up{interface="",local="192.0.2.12",multihop="true",peer="192.0.2.1",vrf="default"}`:      0,
	})
}

func bfdRow(peer, local string, multihop bool) string {
	return fmt.Sprintf(`{"peer":%q,"vrf":"default","local":%q,"multihop":%t,"status":"up","control-packet-input":5}`, peer, local, multihop)
}

func TestBFDDuplicateIdentitiesFail(t *testing.T) {
	a := bfdRow("192.0.2.1", "192.0.2.10", true)
	for name, tc := range map[string]struct{ peers, counters string }{
		"duplicate session":     {"[" + a + "," + a + "]", "[]"},
		"duplicate counter row": {"[]", "[" + a + "," + a + "]"},
	} {
		if _, err := collectBFD(context.Background(), fake(map[string]string{peersCmd: tc.peers, countersCmd: tc.counters})); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestBFDSessionInOnlyOneReadIsLeftOut(t *testing.T) {
	// The counters row belongs to another session, so this session keeps its
	// state and loses its counters for one scrape; the collector still succeeds.
	ms, err := collectBFD(context.Background(), fake(map[string]string{
		peersCmd:    "[" + bfdRow("192.0.2.1", "192.0.2.10", true) + "]",
		countersCmd: "[" + bfdRow("192.0.2.8", "192.0.2.10", true) + "]"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := series(t, ms); len(got) != 1 {
		t.Errorf("want only the session state, got %v", got)
	}
}

func TestBFDMissingCounterIsOmittedNotZero(t *testing.T) {
	row := `{"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","multihop":false,"interface":"eth0","control-packet-input":9}`
	ms, err := collectBFD(context.Background(), fake(map[string]string{
		peersCmd:    `[{"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","multihop":false,"interface":"eth0","status":"up"}]`,
		countersCmd: "[" + row + "]"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		`frrk8s_bfd_control_packet_input{interface="eth0",local="192.0.2.10",multihop="false",peer="192.0.2.1",vrf="default"}`: 9})
	absent(t, got, "frrk8s_bfd_echo_", "frrk8s_bfd_zebra", "frrk8s_bfd_control_packet_output", "frrk8s_bfd_session_up_events", "frrk8s_bfd_session_down_events")
}

func TestBFDMultihopFromRealFRR(t *testing.T) {
	// Real FRR: a multihop session has no interface key, and both replies
	// carry the same identity, which is what the join relies on.
	ms, err := collectBFD(context.Background(), fake(map[string]string{
		peersCmd: "@bfd_multihop_peers.json", countersCmd: "@bfd_multihop_counters.json"}))
	if err != nil {
		t.Fatal(err)
	}
	const id = `{interface="",local="10.80.0.2",multihop="true",peer="10.80.0.3",vrf="default"}`
	expect(t, series(t, ms), map[string]float64{
		"frrk8s_bfd_session_up" + id:           1,
		"frrk8s_bfd_control_packet_input" + id: 49,
	})
}

func TestFailedCollectorDropsPartialData(t *testing.T) {
	partial := Collector{"partial", func(context.Context, Runner) ([]prometheus.Metric, error) {
		return []prometheus.Metric{prometheus.MustNewConstMetric(bgpSessionUp, prometheus.GaugeValue, 1, "p", "v")}, fmt.Errorf("second read failed")
	}}
	got := series(t, Gather(context.Background(), nil, []Collector{partial}, discard))
	absent(t, got, "frrk8s_bgp_")
	expect(t, got, map[string]float64{`frrk8s_scrape_collector_success{collector="partial"}`: 0})
}

func TestBFDSessionWithoutStatusIsMalformed(t *testing.T) {
	row := `{"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","multihop":true}`
	if _, err := collectBFD(context.Background(), fake(map[string]string{peersCmd: "[" + row + "]", countersCmd: "[]"})); err == nil {
		t.Error("a session with no status was reported as down")
	}
}

func TestEVPNFromRealFRR(t *testing.T) {
	ms, err := collectEVPN(context.Background(), fake(map[string]string{"show evpn vni json": "@evpn_vni.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		`frrk8s_evpn_vni_info{interface="vxlan10100",type="L2",vni="10100",vrf="default"}`: 1,
		`frrk8s_evpn_vni_info{interface="vxlan50001",type="L3",vni="50001",vrf="red"}`:     1,
		`frrk8s_evpn_macs{vni="10100",vrf="default"}`:                                      1,
		`frrk8s_evpn_neighbors{vni="10100",vrf="default"}`:                                 0,
		`frrk8s_evpn_remote_vteps{vni="10100",vrf="default"}`:                              1,
	})
	// For an L3 VNI the same fields mean router MACs and next hops.
	absent(t, got, `frrk8s_evpn_macs{vni="50001"`, `frrk8s_evpn_neighbors{vni="50001"`, `frrk8s_evpn_remote_vteps{vni="50001"`)
}

func TestEVPNEmptyAndPartial(t *testing.T) {
	ms, err := collectEVPN(context.Background(), fake(map[string]string{"show evpn vni json": "{}"}))
	if err != nil || len(ms) != 0 {
		t.Errorf("no VNIs: %d series, err %v", len(ms), err)
	}
	ms, err = collectEVPN(context.Background(), fake(map[string]string{"show evpn vni json": `{"7":{"type":"L2","vxlanIf":"v7","tenantVrf":"default"}}`}))
	if err != nil {
		t.Fatal(err)
	}
	// Counts FRR did not report are absent, not zero.
	if got := series(t, ms); len(got) != 1 {
		t.Errorf("want only the inventory series, got %v", got)
	}
}

func TestOneFailingCollectorDoesNotHideTheOthers(t *testing.T) {
	run := fake(map[string]string{bgpCmd: "@bgp_neighbors.json", "show evpn vni json": "@evpn_vni.json"}) // no BFD
	got := series(t, Gather(context.Background(), run, all, discard))
	expect(t, got, map[string]float64{
		`frrk8s_scrape_collector_success{collector="bgp"}`:  1,
		`frrk8s_scrape_collector_success{collector="bfd"}`:  0,
		`frrk8s_scrape_collector_success{collector="evpn"}`: 1,
	})
	for _, c := range all {
		if _, ok := got[fmt.Sprintf(`frrk8s_scrape_collector_duration_seconds{collector=%q}`, c.Name)]; !ok {
			t.Errorf("no duration for %s", c.Name)
		}
	}
	absent(t, got, "frrk8s_bfd_")
}

func TestSelectCollectors(t *testing.T) {
	cs, err := Select("bgp, evpn")
	if err != nil || len(cs) != 2 || cs[1].Name != "evpn" {
		t.Errorf("got %v, %v", cs, err)
	}
	for _, bad := range []string{"bgp,ospf", "", "bgp,bgp", "bgp,,evpn"} {
		if _, err := Select(bad); err == nil {
			t.Errorf("Select(%q) accepted", bad)
		}
	}
}

// quiet answers every read with empty but valid output.

// BenchmarkCollectBGP backs the README's scale figure: 2000 neighbors built

// from the real fixture's shape.

func BenchmarkCollectBGP(b *testing.B) {
	raw, err := os.ReadFile("testdata/bgp_neighbors.json")
	if err != nil {
		b.Fatal(err)
	}
	var fixture map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		b.Fatal(err)
	}
	peers := map[string]json.RawMessage{}
	for i := 0; i < 2000; i++ {
		peers[fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256+1)] = fixture["default"]["10.78.0.3"]
	}
	big, _ := json.Marshal(map[string]any{"default": peers})
	run := func(context.Context, string) ([]byte, error) { return big, nil }
	b.SetBytes(int64(len(big)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := collectBGP(context.Background(), run); err != nil {
			b.Fatal(err)
		}
	}
}
