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

func TestMetricContractFromRealFRR(t *testing.T) {
	// This is the public frr-k8s/EGA contract, independent of the descriptors.
	// In particular, prefix _total families are gauges and BGP UPDATEs are counters.
	want := map[string]struct{ kind, labels string }{
		"frrk8s_bgp_session_up":                    {"GAUGE", "peer,vrf"},
		"frrk8s_bgp_announced_prefixes_total":      {"GAUGE", "peer,vrf"},
		"frrk8s_bgp_received_prefixes_total":       {"GAUGE", "peer,vrf"},
		"frrk8s_bgp_family_announced_prefixes":     {"GAUGE", "afi,peer,safi,vrf"},
		"frrk8s_bgp_family_received_prefixes":      {"GAUGE", "afi,peer,safi,vrf"},
		"frrk8s_bgp_opens_sent":                    {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_opens_received":                {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_notifications_sent":            {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_updates_total":                 {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_updates_total_received":        {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_keepalives_sent":               {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_keepalives_received":           {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_route_refresh_sent":            {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_total_sent":                    {"COUNTER", "peer,vrf"},
		"frrk8s_bgp_total_received":                {"COUNTER", "peer,vrf"},
		"frrk8s_bfd_session_up":                    {"GAUGE", "interface,local,multihop,peer,vrf"},
		"frrk8s_bfd_control_packet_input":          {"COUNTER", "interface,local,multihop,peer,vrf"},
		"frrk8s_bfd_control_packet_output":         {"COUNTER", "interface,local,multihop,peer,vrf"},
		"frrk8s_bfd_echo_packet_input":             {"COUNTER", "interface,local,multihop,peer,vrf"},
		"frrk8s_bfd_echo_packet_output":            {"COUNTER", "interface,local,multihop,peer,vrf"},
		"frrk8s_bfd_session_up_events":             {"COUNTER", "interface,local,multihop,peer,vrf"},
		"frrk8s_bfd_session_down_events":           {"COUNTER", "interface,local,multihop,peer,vrf"},
		"frrk8s_bfd_zebra_notifications":           {"COUNTER", "interface,local,multihop,peer,vrf"},
		"frrk8s_evpn_vni_info":                     {"GAUGE", "interface,type,vni,vrf"},
		"frrk8s_evpn_macs":                         {"GAUGE", "vni,vrf"},
		"frrk8s_evpn_neighbors":                    {"GAUGE", "vni,vrf"},
		"frrk8s_evpn_remote_vteps":                 {"GAUGE", "vni,vrf"},
		"frrk8s_evpn_remote_vtep_present":          {"GAUGE", "vni,vrf,vtep"},
		"frrk8s_evpn_es_oper_up":                   {"GAUGE", "esi"},
		"frrk8s_evpn_es_df":                        {"GAUGE", "esi"},
		"frrk8s_scrape_collector_success":          {"GAUGE", "collector"},
		"frrk8s_scrape_collector_duration_seconds": {"GAUGE", "collector"},
	}
	ms := Gather(context.Background(), fake(map[string]string{
		bgpCmd:               "@bgp_neighbors.json",
		peersCmd:             "@bfd_peers.json",
		countersCmd:          "@bfd_counters.json",
		"show evpn vni json": "@evpn_vni_membership.json",
		esCmd:                "@evpn_es_df.json",
	}), all, discard)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(Snapshot(ms))
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		contract, ok := want[f.GetName()]
		if !ok {
			t.Errorf("unexpected metric family %s", f.GetName())
			continue
		}
		delete(want, f.GetName())
		if got := f.GetType().String(); got != contract.kind {
			t.Errorf("%s type = %s, want %s", f.GetName(), got, contract.kind)
		}
		for _, m := range f.Metric {
			var labels []string
			for _, l := range m.Label {
				labels = append(labels, l.GetName())
			}
			if got := strings.Join(labels, ","); got != contract.labels {
				t.Errorf("%s labels = %s, want %s", f.GetName(), got, contract.labels)
			}
		}
	}
	for name := range want {
		t.Errorf("missing metric family %s", name)
	}
}

func TestBGPFromRealFRR(t *testing.T) {
	raw, err := os.ReadFile("testdata/bgp_neighbors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vrfs map[string]any
	if err := json.Unmarshal(raw, &vrfs); err != nil {
		t.Fatal(err)
	}
	// Preserve the captured shape, with distinct counters so source swaps cannot hide.
	stats := vrfs["default"].(map[string]any)["10.78.0.3"].(map[string]any)["messageStats"].(map[string]any)
	for key, value := range map[string]int{
		"opensSent": 11, "opensRecv": 12, "notificationsSent": 13,
		"updatesSent": 14, "updatesRecv": 15, "keepalivesSent": 16,
		"keepalivesRecv": 17, "routeRefreshSent": 18, "totalSent": 72, "totalRecv": 44,
	} {
		stats[key] = value
	}
	raw, err = json.Marshal(vrfs)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := collectBGP(context.Background(), fake(map[string]string{bgpCmd: string(raw)}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	const p = `{peer="10.78.0.3",vrf="default"}`
	expect(t, got, map[string]float64{
		"frrk8s_bgp_session_up" + p:               1,
		"frrk8s_bgp_announced_prefixes_total" + p: 4, // 1 IPv4 + 3 EVPN
		"frrk8s_bgp_received_prefixes_total" + p:  2,
		"frrk8s_bgp_opens_sent" + p:               11,
		"frrk8s_bgp_opens_received" + p:           12,
		"frrk8s_bgp_notifications_sent" + p:       13,
		"frrk8s_bgp_updates_total" + p:            14,
		"frrk8s_bgp_updates_total_received" + p:   15,
		"frrk8s_bgp_keepalives_sent" + p:          16,
		"frrk8s_bgp_keepalives_received" + p:      17,
		"frrk8s_bgp_route_refresh_sent" + p:       18,
		"frrk8s_bgp_total_sent" + p:               72,
		"frrk8s_bgp_total_received" + p:           44,
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

func TestBGPIPv6AndVPNFromRealFRR(t *testing.T) {
	ms, err := collectBGP(context.Background(), fake(map[string]string{bgpCmd: "@bgp_families.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		`frrk8s_bgp_session_up{peer="10.193.0.3",vrf="default"}`:                                          1,
		`frrk8s_bgp_family_received_prefixes{afi="ipv6",peer="10.193.0.3",safi="unicast",vrf="default"}`:  1,
		`frrk8s_bgp_family_announced_prefixes{afi="ipv6",peer="10.193.0.3",safi="unicast",vrf="default"}`: 2,
		`frrk8s_bgp_family_received_prefixes{afi="ipv4",peer="10.193.0.3",safi="vpn",vrf="default"}`:      1,
		`frrk8s_bgp_family_announced_prefixes{afi="ipv4",peer="10.193.0.3",safi="vpn",vrf="default"}`:     2,
		`frrk8s_bgp_received_prefixes_total{peer="10.193.0.3",vrf="default"}`:                             2,
		`frrk8s_bgp_announced_prefixes_total{peer="10.193.0.3",vrf="default"}`:                            4,
	})
}

func TestBGPFamilies(t *testing.T) {
	reply := `{
	  "default": {"vrfId": 0, "vrfName": "default",
	    "192.0.2.1": {"bgpState": "Established", "messageStats": {"totalSent": 5, "opensSent": null},
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

func TestBGPBookkeepingNamesCanBeInterfacePeersFromRealFRR(t *testing.T) {
	ms, err := collectBGP(context.Background(), fake(map[string]string{bgpCmd: "@bgp_reserved_interfaces.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	for _, peer := range []string{"vrfId", "vrfName", "10.201.13.3"} {
		expect(t, got, map[string]float64{
			fmt.Sprintf(`frrk8s_bgp_session_up{peer=%q,vrf="default"}`, peer): 0,
		})
	}
}

func TestBGPUnknownKernelVRFFromRealFRR(t *testing.T) {
	// FRR reports vrfId -1 while the BGP VRF is configured without a kernel VRF.
	ms, err := collectBGP(context.Background(), fake(map[string]string{bgpCmd: "@bgp_unknown_vrf.json"}))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, series(t, ms), map[string]float64{
		`frrk8s_bgp_session_up{peer="192.0.2.10",vrf="absent"}`: 0,
	})
}

func TestMalformedReadsEmitNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		c       Collector
		replies map[string]string
	}{
		"bgp not json":      {all[0], map[string]string{bgpCmd: "not json"}},
		"bgp null":          {all[0], map[string]string{bgpCmd: "null"}},
		"bgp null vrf":      {all[0], map[string]string{bgpCmd: `{"default":null}`}},
		"bgp empty peer":    {all[0], map[string]string{bgpCmd: `{"default":{"192.0.2.1":{}}}`}},
		"bgp null peer":     {all[0], map[string]string{bgpCmd: `{"default":{"192.0.2.1":null}}`}},
		"bgp wrong type":    {all[0], map[string]string{bgpCmd: `{"default":{"192.0.2.1":{"messageStats":"x"}}}`}},
		"bfd not json":      {all[1], map[string]string{"show bfd peers json": "[", "show bfd peers counters json": "[]"}},
		"bfd null peers":    {all[1], map[string]string{peersCmd: "null", countersCmd: "[]"}},
		"bfd null counters": {all[1], map[string]string{peersCmd: "[]", countersCmd: "null"}},
		"bfd command fails": {all[1], map[string]string{"show bfd peers json": "[]"}},
		"evpn not json":     {all[2], map[string]string{"show evpn vni json": "<html>"}},
		"evpn null":         {all[2], map[string]string{"show evpn vni json": "null"}},
		"evpn empty vni":    {all[2], map[string]string{"show evpn vni json": `{"not-a-vni":{}}`}},
		"evpn wrong shape":  {all[2], map[string]string{"show evpn vni json": "[1]"}},
	} {
		if tc.c.Name == "evpn" {
			tc.replies[esCmd] = "@evpn_es_empty.json"
		}
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

func TestCorruptFixtureFieldsFailOnlyTheirCollector(t *testing.T) {
	// Corrupt real captures: unknown/absent measurements must not turn into
	// zero, and malformed identities must not become plausible inventory.
	const evpnCmd = "show evpn vni json"
	for _, tc := range []struct {
		name, collector, command, from, to string
	}{
		{"bgp missing state", "bgp", bgpCmd, `"bgpState":"Established"`, `"bgpState":null`},
		{"bgp empty vrf", "bgp", bgpCmd, `"default":`, `"":`},
		{"bgp empty peer", "bgp", bgpCmd, `"10.78.0.3":`, `"":`},
		{"bgp negative count", "bgp", bgpCmd, `"acceptedPrefixCounter":1`, `"acceptedPrefixCounter":-1`},
		{"bgp fractional count", "bgp", bgpCmd, `"sentPrefixCounter":1`, `"sentPrefixCounter":1.5`},
		{"bgp negative counter", "bgp", bgpCmd, `"opensSent":2`, `"opensSent":-2`},
		{"bfd missing id", "bfd", peersCmd, `"id":2149748673`, `"id":null`},
		{"bfd missing peer", "bfd", peersCmd, `"peer":"10.78.0.3"`, `"peer":null`},
		{"bfd missing mode", "bfd", peersCmd, `"multihop":false`, `"multihop":null`},
		{"bfd missing status", "bfd", peersCmd, `"status":"up"`, `"status":null`},
		{"bfd counter missing id", "bfd", countersCmd, `"id":2149748673`, `"id":null`},
		{"bfd counter missing peer", "bfd", countersCmd, `"peer":"10.78.0.3"`, `"peer":null`},
		{"bfd counter missing mode", "bfd", countersCmd, `"multihop":false`, `"multihop":null`},
		{"bfd negative counter", "bfd", countersCmd, `"control-packet-input":107`, `"control-packet-input":-1`},
		{"bfd fractional counter", "bfd", countersCmd, `"control-packet-input":107`, `"control-packet-input":1.5`},
		{"evpn invalid key", "evpn", evpnCmd, `"10100":`, `"not-a-vni":`},
		{"evpn mismatched key", "evpn", evpnCmd, `"vni":10100`, `"vni":10101`},
		{"evpn zero vni", "evpn", evpnCmd, "\"10100\":{\n    \"vni\":10100", "\"0\":{\n    \"vni\":0"},
		{"evpn out of range", "evpn", evpnCmd, "\"10100\":{\n    \"vni\":10100", "\"16777216\":{\n    \"vni\":16777216"},
		{"evpn missing type", "evpn", evpnCmd, `"type":"L2"`, `"type":null`},
		{"evpn invalid type", "evpn", evpnCmd, `"type":"L2"`, `"type":"other"`},
		{"evpn missing vrf", "evpn", evpnCmd, `"tenantVrf":"default"`, `"tenantVrf":null`},
		{"evpn missing interface", "evpn", evpnCmd, `"vxlanIf":"vxlan10100"`, `"vxlanIf":null`},
		{"evpn negative macs", "evpn", evpnCmd, `"numMacs":1`, `"numMacs":-1`},
		{"evpn fractional neighbors", "evpn", evpnCmd, `"numArpNd":0`, `"numArpNd":0.5`},
		{"evpn negative vteps", "evpn", evpnCmd, `"numRemoteVteps":1`, `"numRemoteVteps":-1`},
		{"evpn fractional vteps", "evpn", evpnCmd, `"numRemoteVteps":1`, `"numRemoteVteps":1.5`},
		{"evpn invalid vteps", "evpn", evpnCmd, `"numRemoteVteps":1`, `"numRemoteVteps":"n/a"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replies := map[string]string{bgpCmd: "@bgp_neighbors.json", peersCmd: "@bfd_peers.json",
				countersCmd: "@bfd_counters.json", evpnCmd: "@evpn_vni.json", esCmd: "@evpn_es_empty.json"}
			raw, err := fake(replies)(context.Background(), tc.command)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), tc.from) {
				t.Fatalf("fixture does not contain %s", tc.from)
			}
			replies[tc.command] = strings.Replace(string(raw), tc.from, tc.to, 1)
			got := series(t, Gather(context.Background(), fake(replies), all, discard))
			for _, c := range all {
				want := 1.0
				if c.Name == tc.collector {
					want = 0
				}
				expect(t, got, map[string]float64{fmt.Sprintf(`frrk8s_scrape_collector_success{collector=%q}`, c.Name): want})
			}
			absent(t, got, "frrk8s_"+tc.collector+"_")
		})
	}
}

func TestBFDFromRealFRR(t *testing.T) {
	raw, err := os.ReadFile("testdata/bfd_counters.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	// Keep the real identity and shape, with distinct values for every source.
	for key, value := range map[string]int{
		"control-packet-input": 101, "control-packet-output": 102,
		"echo-packet-input": 103, "echo-packet-output": 104,
		"session-up": 106, "session-down": 105, "zebra-notifications": 107,
	} {
		rows[0][key] = value
	}
	raw, err = json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := collectBFD(context.Background(), fake(map[string]string{peersCmd: "@bfd_peers.json", countersCmd: string(raw)}))
	if err != nil {
		t.Fatal(err)
	}
	const id = `{interface="eth0",local="10.78.0.2",multihop="false",peer="10.78.0.3",vrf="default"}`
	expect(t, series(t, ms), map[string]float64{
		"frrk8s_bfd_session_up" + id:            1,
		"frrk8s_bfd_control_packet_input" + id:  101,
		"frrk8s_bfd_control_packet_output" + id: 102,
		"frrk8s_bfd_echo_packet_input" + id:     103,
		"frrk8s_bfd_echo_packet_output" + id:    104,
		"frrk8s_bfd_session_up_events" + id:     106,
		"frrk8s_bfd_session_down_events" + id:   105,
		"frrk8s_bfd_zebra_notifications" + id:   107,
	})
}

func TestBFDSBFDDoesNotSatisfyOrdinarySessionHealth(t *testing.T) {
	// This real SBFD-init session is up, but its name/mode cannot be represented
	// by the ordinary BFD label identity. Reject even without a simultaneous collision.
	for _, mixed := range []bool{false, true} {
		replies := map[string]string{peersCmd: "@bfd_sbfd_peers.json", countersCmd: "@bfd_sbfd_counters.json"}
		if mixed {
			for command, ordinary := range map[string]string{peersCmd: "@bfd_peers.json", countersCmd: "@bfd_counters.json"} {
				named, err := fake(replies)(context.Background(), command)
				if err != nil {
					t.Fatal(err)
				}
				normal, err := fake(map[string]string{command: ordinary})(context.Background(), command)
				if err != nil {
					t.Fatal(err)
				}
				var a, b []json.RawMessage
				if err := json.Unmarshal(named, &a); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(normal, &b); err != nil {
					t.Fatal(err)
				}
				both, err := json.Marshal(append(b, a...))
				if err != nil {
					t.Fatal(err)
				}
				replies[command] = string(both)
			}
		}
		if ms, err := collectBFD(context.Background(), fake(replies)); err == nil || len(ms) != 0 {
			t.Errorf("mixed=%v: accepted unsupported mode: %d metrics, error %v", mixed, len(ms), err)
		}
		got := series(t, Gather(context.Background(), fake(replies), all[1:2], discard))
		expect(t, got, map[string]float64{`frrk8s_scrape_collector_success{collector="bfd"}`: 0})
		absent(t, got, "frrk8s_bfd_")
	}
}

const (
	peersCmd    = "show bfd peers json"
	countersCmd = "show bfd peers counters json"
)

func TestBFDSessionsToOnePeerAndBFDOnlyVRFFromRealFRR(t *testing.T) {
	// Four sessions to one peer, including a BFD-only VRF, plus a session
	// without a local address or interface. No BGP discovery read is available.
	ms, err := collectBFD(context.Background(), fake(map[string]string{
		peersCmd: "@bfd_identity_peers.json", countersCmd: "@bfd_identity_counters.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	for _, labels := range []string{
		`{interface="dummy0",local="192.0.2.10",multihop="false",peer="192.0.2.1",vrf="default"}`,
		`{interface="",local="192.0.2.11",multihop="true",peer="192.0.2.1",vrf="default"}`,
		`{interface="",local="192.0.2.12",multihop="true",peer="192.0.2.1",vrf="default"}`,
		`{interface="dummy-blue",local="192.0.2.20",multihop="false",peer="192.0.2.1",vrf="blue"}`,
		`{interface="",local="",multihop="false",peer="192.0.2.2",vrf="default"}`,
	} {
		expect(t, got, map[string]float64{
			"frrk8s_bfd_session_up" + labels:           0,
			"frrk8s_bfd_control_packet_input" + labels: 0,
		})
	}
	if len(got) != 5*8 {
		t.Errorf("got %d series, want 8 for each of 5 sessions", len(got))
	}
}

func bfdRow(id uint32, peer, local string, multihop bool) string {
	return fmt.Sprintf(`{"id":%d,"peer":%q,"vrf":"default","local":%q,"multihop":%t,"status":"up","control-packet-input":5}`, id, peer, local, multihop)
}

func TestBFDDuplicateIdentitiesFail(t *testing.T) {
	a := bfdRow(1, "192.0.2.1", "192.0.2.10", true)
	b := strings.Replace(a, `"id":1`, `"id":2`, 1)
	for name, tc := range map[string]struct{ peers, counters string }{
		"duplicate session":         {"[" + a + "," + a + "]", "[" + a + "]"},
		"duplicate counter row":     {"[]", "[" + a + "," + a + "]"},
		"distinct ids share labels": {"[" + a + "," + b + "]", "[" + a + "," + b + "]"},
	} {
		if ms, err := collectBFD(context.Background(), fake(map[string]string{peersCmd: tc.peers, countersCmd: tc.counters})); err == nil || len(ms) != 0 {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestBFDInvalidIdentityInBothReads(t *testing.T) {
	for _, field := range []string{`"id":2149748673`, `"peer":"10.78.0.3"`, `"multihop":false`} {
		t.Run(field, func(t *testing.T) {
			replies := map[string]string{peersCmd: "@bfd_peers.json", countersCmd: "@bfd_counters.json"}
			for command := range replies {
				raw, err := fake(replies)(context.Background(), command)
				if err != nil {
					t.Fatal(err)
				}
				replies[command] = strings.Replace(string(raw), field, strings.SplitN(field, ":", 2)[0]+":null", 1)
			}
			if ms, err := collectBFD(context.Background(), fake(replies)); err == nil || len(ms) != 0 {
				t.Errorf("invalid identity: %d metrics, error %v", len(ms), err)
			}
		})
	}
}

func TestBFDSnapshotMismatchFailsAtomically(t *testing.T) {
	a := bfdRow(1, "192.0.2.1", "192.0.2.10", true)
	b := bfdRow(2, "192.0.2.2", "192.0.2.20", true)
	for name, replies := range map[string][2]string{
		"missing counters":     {"[" + a + "," + b + "]", "[" + a + "]"},
		"missing session":      {"[" + a + "]", "[" + a + "," + b + "]"},
		"recreated session":    {"[" + a + "]", "[" + strings.Replace(a, `"id":1`, `"id":2`, 1) + "]"},
		"changed identity":     {"[" + a + "]", "[" + strings.Replace(a, "192.0.2.10", "192.0.2.11", 1) + "]"},
		"reused session id":    {"[" + a + "," + strings.Replace(b, `"id":2`, `"id":1`, 1) + "]", "[" + a + "," + b + "]"},
		"duplicate counter id": {"[" + a + "," + b + "]", "[" + a + "," + strings.Replace(b, `"id":2`, `"id":1`, 1) + "]"},
	} {
		t.Run(name, func(t *testing.T) {
			run := fake(map[string]string{peersCmd: replies[0], countersCmd: replies[1]})
			if ms, err := collectBFD(context.Background(), run); err == nil || len(ms) != 0 {
				t.Errorf("mismatched snapshot: %d metrics, error %v", len(ms), err)
			}
			got := series(t, Gather(context.Background(), run, all[1:2], discard))
			expect(t, got, map[string]float64{`frrk8s_scrape_collector_success{collector="bfd"}`: 0})
			absent(t, got, "frrk8s_bfd_")
		})
	}
}

func TestBFDMissingCounterIsOmittedNotZero(t *testing.T) {
	row := `{"id":1,"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","multihop":false,"interface":"eth0","control-packet-input":9}`
	ms, err := collectBFD(context.Background(), fake(map[string]string{
		peersCmd:    `[{"id":1,"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","multihop":false,"interface":"eth0","status":"up"}]`,
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

func TestCancellationAfterReadDropsParsedData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := fake(map[string]string{bgpCmd: "@bgp_neighbors.json"})
	got := series(t, Gather(ctx, func(ctx context.Context, command string) ([]byte, error) {
		out, err := run(ctx, command)
		cancel() // The CLI finishes just as cancellation arrives, before parsing.
		return out, err
	}, all[:1], discard))
	if len(got) != 2 {
		t.Errorf("cancelled collector emitted %d series, want only two status series", len(got))
	}
	expect(t, got, map[string]float64{`frrk8s_scrape_collector_success{collector="bgp"}`: 0})
}

func TestBFDSessionWithoutStatusIsMalformed(t *testing.T) {
	row := `{"id":1,"peer":"192.0.2.1","vrf":"default","local":"192.0.2.10","multihop":true}`
	if _, err := collectBFD(context.Background(), fake(map[string]string{peersCmd: "[" + row + "]", countersCmd: "[]"})); err == nil {
		t.Error("a session with no status was reported as down")
	}
}

func TestOneFailingCollectorDoesNotHideTheOthers(t *testing.T) {
	run := fake(map[string]string{bgpCmd: "@bgp_neighbors.json", "show evpn vni json": "@evpn_vni.json", esCmd: "@evpn_es_empty.json"}) // no BFD
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
