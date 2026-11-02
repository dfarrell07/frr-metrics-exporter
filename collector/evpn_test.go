// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	vniCmd  = "show evpn vni json"
	esCmd   = "show evpn es detail json"
	testESI = "03:44:38:39:ff:ff:01:00:00:01"
)

func TestEVPNFromRealFRR(t *testing.T) {
	ms, err := collectEVPN(context.Background(), fake(map[string]string{vniCmd: "@evpn_vni.json", esCmd: "@evpn_es_empty.json"}))
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
		`frrk8s_evpn_remote_vtep_present{vni="10100",vrf="default",vtep="10.78.0.3"}`:      1,
	})
	// For an L3 VNI the same fields mean router MACs and next hops.
	absent(t, got, `frrk8s_evpn_macs{vni="50001"`, `frrk8s_evpn_neighbors{vni="50001"`, `frrk8s_evpn_remote_vteps{vni="50001"`, `frrk8s_evpn_remote_vtep_present{vni="50001"`)
}

func TestEVPNMembershipScopedToVNIAndVRFFromRealFRR(t *testing.T) {
	ms, err := collectEVPN(context.Background(), fake(map[string]string{vniCmd: "@evpn_vni_membership.json", esCmd: "@evpn_es_empty.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		`frrk8s_evpn_remote_vtep_present{vni="10100",vrf="default",vtep="10.77.0.3"}`: 1,
		`frrk8s_evpn_remote_vtep_present{vni="10100",vrf="default",vtep="10.77.0.4"}`: 1,
		`frrk8s_evpn_remote_vtep_present{vni="10200",vrf="red",vtep="10.77.0.3"}`:     1,
		`frrk8s_evpn_remote_vteps{vni="10100",vrf="default"}`:                         2,
		`frrk8s_evpn_remote_vteps{vni="10200",vrf="red"}`:                             1,
	})
	var memberships int
	for key := range got {
		if strings.HasPrefix(key, "frrk8s_evpn_remote_vtep_present{") {
			memberships++
		}
	}
	if memberships != 3 {
		t.Errorf("got %d memberships, want 3", memberships)
	}
}

func TestEVPNEthernetSegmentsFromRealFRR(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    map[string]float64
	}{
		{"evpn_es_df.json", map[string]float64{"evpn_es_oper_up": 1, "evpn_es_df": 1}},
		{"evpn_es_non_df.json", map[string]float64{"evpn_es_oper_up": 1, "evpn_es_df": 0}},
		{"evpn_es_down.json", map[string]float64{"evpn_es_oper_up": 0}},
		{"evpn_es_bypass.json", map[string]float64{"evpn_es_oper_up": 1}},
		{"evpn_es_pending.json", map[string]float64{"evpn_es_oper_up": 1}},
		{"evpn_es_unready.json", map[string]float64{"evpn_es_oper_up": 1}},
		{"evpn_es_remote.json", nil},
		{"evpn_es_empty.json", nil},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			// Local ES state can exist without any local VNIs.
			ms, err := collectEVPN(context.Background(), fake(map[string]string{vniCmd: "{}", esCmd: "@" + tc.fixture}))
			if err != nil {
				t.Fatal(err)
			}
			got := series(t, ms)
			for name, value := range tc.want {
				expect(t, got, map[string]float64{fmt.Sprintf(`frrk8s_%s{esi=%q}`, name, testESI): value})
			}
			if len(got) != len(tc.want) {
				t.Errorf("got %v, want only %v", got, tc.want)
			}
		})
	}
}

func TestEVPNMACOnlySegmentDoesNotHideVNIObservations(t *testing.T) {
	ms, err := collectEVPN(context.Background(), fake(map[string]string{vniCmd: "@evpn_vni.json", esCmd: "@evpn_es_mac_only.json"}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		`frrk8s_evpn_vni_info{interface="vxlan10100",type="L2",vni="10100",vrf="default"}`: 1,
		`frrk8s_evpn_remote_vtep_present{vni="10100",vrf="default",vtep="10.78.0.3"}`:      1,
	})
	absent(t, got, "frrk8s_evpn_es_")
}

func TestEVPNMultipleLocalSegmentsStayDistinct(t *testing.T) {
	a, b := fixtureObject(t, "evpn_es_df.json"), fixtureObject(t, "evpn_es_non_df.json")
	secondESI := "03:44:38:39:ff:ff:01:00:00:02"
	b["esi"] = secondESI
	ms, err := collectEVPN(context.Background(), fake(map[string]string{vniCmd: "{}", esCmd: encodeJSON(t, []any{a, b})}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{
		fmt.Sprintf(`frrk8s_evpn_es_oper_up{esi=%q}`, testESI):   1,
		fmt.Sprintf(`frrk8s_evpn_es_df{esi=%q}`, testESI):        1,
		fmt.Sprintf(`frrk8s_evpn_es_oper_up{esi=%q}`, secondESI): 1,
		fmt.Sprintf(`frrk8s_evpn_es_df{esi=%q}`, secondESI):      0,
	})
	if len(got) != 4 {
		t.Errorf("got %d series, want 4", len(got))
	}
}

func TestEVPNCancellationBetweenReadsDropsEverything(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	read := fake(map[string]string{vniCmd: "@evpn_vni.json", esCmd: "@evpn_es_df.json"})
	run := func(ctx context.Context, command string) ([]byte, error) {
		out, err := read(ctx, command)
		if command == vniCmd {
			cancel()
		}
		return out, err
	}
	if ms, err := collectEVPN(ctx, run); !errors.Is(err, context.Canceled) || len(ms) != 0 {
		t.Errorf("cancelled between reads: %d metrics, error %v", len(ms), err)
	}
}

// fixtureObject copies a real row so malformed-input and omission tests do not
// invent a second JSON schema. The capture itself remains unchanged.
func fixtureObject(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s: want one row", name)
	}
	return rows[0]
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestEVPNRejectsMalformedEthernetSegmentsAtomically(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"missing esi":            func(s map[string]any) { delete(s, "esi") },
		"null esi":               func(s map[string]any) { s["esi"] = nil },
		"wrong esi type":         func(s map[string]any) { s["esi"] = 7 },
		"invalid esi":            func(s map[string]any) { s["esi"] = "not-an-esi" },
		"wrong esi length":       func(s map[string]any) { s["esi"] = "03:44:38:39:ff:ff:01:00:01" },
		"wrong esi separators":   func(s map[string]any) { s["esi"] = strings.ReplaceAll(testESI, ":", "-") },
		"zero esi":               func(s map[string]any) { s["esi"] = "00:00:00:00:00:00:00:00:00:00" },
		"missing flags":          func(s map[string]any) { delete(s, "flags") },
		"null flags":             func(s map[string]any) { s["flags"] = nil },
		"wrong flags type":       func(s map[string]any) { s["flags"] = "local" },
		"null flag":              func(s map[string]any) { s["flags"] = []any{"local", nil} },
		"no owner":               func(s map[string]any) { s["flags"] = []string{"operUp"} },
		"remote with local port": func(s map[string]any) { s["flags"] = []string{"remote"} },
		"empty access port":      func(s map[string]any) { s["accessPort"] = "" },
		"wrong access port type": func(s map[string]any) { s["accessPort"] = 7 },
		"contradictory role":     func(s map[string]any) { s["flags"] = []string{"local", "df", "nonDF"} },
		"bad timer type":         func(s map[string]any) { s["dfDelayTimer"] = 3 },
		"null timer":             func(s map[string]any) { s["dfDelayTimer"] = nil },
		"empty timer":            func(s map[string]any) { s["dfDelayTimer"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			s := fixtureObject(t, "evpn_es_df.json")
			change(s)
			assertEVPNFailure(t, map[string]string{vniCmd: "@evpn_vni.json", esCmd: encodeJSON(t, []any{s})})
		})
	}
	for _, reply := range []string{"[", "null", "{}", "[null]", "% Unknown command\n[]", "[] trailing"} {
		t.Run(reply, func(t *testing.T) { assertEVPNFailure(t, map[string]string{vniCmd: "@evpn_vni.json", esCmd: reply}) })
	}
	// A failed second read must also drop the VNI and membership results.
	assertEVPNFailure(t, map[string]string{vniCmd: "@evpn_vni.json"})

	// Repeated ESIs fail even when one row is remote-only or differently cased.
	a, b := fixtureObject(t, "evpn_es_df.json"), fixtureObject(t, "evpn_es_remote.json")
	b["esi"] = strings.ToUpper(testESI)
	assertEVPNFailure(t, map[string]string{vniCmd: "@evpn_vni.json", esCmd: encodeJSON(t, []any{a, b})})
}

func assertEVPNFailure(t *testing.T, replies map[string]string) {
	t.Helper()
	if ms, err := collectEVPN(context.Background(), fake(replies)); err == nil || len(ms) != 0 {
		t.Errorf("failed EVPN read: %d metrics, error %v", len(ms), err)
	}
	got := series(t, Gather(context.Background(), fake(replies), all[2:], discard))
	expect(t, got, map[string]float64{`frrk8s_scrape_collector_success{collector="evpn"}`: 0})
	absent(t, got, "frrk8s_evpn_")
}

func TestEVPNUnknownFlagsAndMissingRole(t *testing.T) {
	s := fixtureObject(t, "evpn_es_df.json")
	flags := []string{"local", "readyForBgp", "operUp", "futureFlag"}
	s["flags"], s["esi"], s["futureField"] = flags, strings.ToUpper(testESI), "ignored"
	ms, err := collectEVPN(context.Background(), fake(map[string]string{vniCmd: "{}", esCmd: encodeJSON(t, []any{s})}))
	if err != nil {
		t.Fatal(err)
	}
	got := series(t, ms)
	expect(t, got, map[string]float64{fmt.Sprintf(`frrk8s_evpn_es_oper_up{esi=%q}`, testESI): 1})
	absent(t, got, "frrk8s_evpn_es_df")
}

func TestEVPNVTEPMembershipOmissionsAndInvalidData(t *testing.T) {
	raw, err := os.ReadFile("testdata/evpn_vni.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		change            func(map[string]any)
		fail              bool
		count, membership bool
	}{
		"absent list":      {func(v map[string]any) { delete(v, "remoteVteps") }, false, true, false},
		"null list":        {func(v map[string]any) { v["remoteVteps"] = nil }, false, true, false},
		"absent count":     {func(v map[string]any) { delete(v, "numRemoteVteps") }, false, false, true},
		"null count":       {func(v map[string]any) { v["numRemoteVteps"] = nil }, false, false, true},
		"empty list":       {func(v map[string]any) { v["remoteVteps"], v["numRemoteVteps"] = []string{}, 0 }, false, true, false},
		"invalid ip":       {func(v map[string]any) { v["remoteVteps"] = []string{"not-an-ip"} }, true, false, false},
		"scoped ip":        {func(v map[string]any) { v["remoteVteps"] = []string{"fe80::1%eth0"} }, true, false, false},
		"null ip":          {func(v map[string]any) { v["remoteVteps"] = []any{nil} }, true, false, false},
		"wrong list type":  {func(v map[string]any) { v["remoteVteps"] = "10.78.0.3" }, true, false, false},
		"wrong entry type": {func(v map[string]any) { v["remoteVteps"] = []int{1} }, true, false, false},
		"count mismatch":   {func(v map[string]any) { v["numRemoteVteps"] = 2 }, true, false, false},
		"list mismatch":    {func(v map[string]any) { v["remoteVteps"] = []string{} }, true, false, false},
		"duplicate ip":     {func(v map[string]any) { v["remoteVteps"], v["numRemoteVteps"] = []string{"10.78.0.3", "10.78.0.3"}, 2 }, true, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			var vnis map[string]map[string]any
			if err := json.Unmarshal(raw, &vnis); err != nil {
				t.Fatal(err)
			}
			tc.change(vnis["10100"])
			replies := map[string]string{vniCmd: encodeJSON(t, vnis), esCmd: "@evpn_es_empty.json"}
			if tc.fail {
				assertEVPNFailure(t, replies)
				return
			}
			ms, err := collectEVPN(context.Background(), fake(replies))
			if err != nil {
				t.Fatal(err)
			}
			got := series(t, ms)
			for key, want := range map[string]bool{
				`frrk8s_evpn_remote_vteps{vni="10100",vrf="default"}`:                         tc.count,
				`frrk8s_evpn_remote_vtep_present{vni="10100",vrf="default",vtep="10.78.0.3"}`: tc.membership,
			} {
				if _, present := got[key]; present != want {
					t.Errorf("%s present = %v, want %v", key, present, want)
				}
			}
		})
	}
}

func TestEVPNEmptyAndPartial(t *testing.T) {
	ms, err := collectEVPN(context.Background(), fake(map[string]string{vniCmd: "{}", esCmd: "@evpn_es_empty.json"}))
	if err != nil || len(ms) != 0 {
		t.Errorf("no VNIs: %d series, err %v", len(ms), err)
	}
	ms, err = collectEVPN(context.Background(), fake(map[string]string{esCmd: "@evpn_es_empty.json", vniCmd: `{"7":{"vni":7,"type":"L2","vxlanIf":"v7","tenantVrf":"default"}}`}))
	if err != nil {
		t.Fatal(err)
	}
	// Counts FRR did not report are absent, not zero.
	if got := series(t, ms); len(got) != 1 {
		t.Errorf("want only the inventory series, got %v", got)
	}
}

// Hold VNI count fixed while increasing advertised VTEPs. BGP peer count is
// not a bound on membership cardinality when a relay advertises many VTEPs.
func BenchmarkCollectEVPN(b *testing.B) {
	raw, err := os.ReadFile("testdata/evpn_vni_membership.json")
	if err != nil {
		b.Fatal(err)
	}
	var fixture map[string]evpnVNI
	if err := json.Unmarshal(raw, &fixture); err != nil {
		b.Fatal(err)
	}
	empty, err := os.ReadFile("testdata/evpn_es_empty.json")
	if err != nil {
		b.Fatal(err)
	}
	for _, count := range []int{1, 256} {
		b.Run(fmt.Sprintf("64_VNIs_%d_VTEPs", count), func(b *testing.B) {
			vteps := make([]string, count)
			for i := range vteps {
				vteps[i] = fmt.Sprintf("10.200.%d.%d", i/254, i%254+1)
			}
			vnis := make(map[string]evpnVNI, 64)
			for i := 0; i < 64; i++ {
				v := fixture["10100"]
				v.VNI, v.VxlanIf = uint32(10001+i), fmt.Sprintf("vxlan%d", 10001+i)
				v.VTEPs, v.RemoteVTEPs = vteps, json.RawMessage(fmt.Sprint(count))
				vnis[fmt.Sprint(v.VNI)] = v
			}
			payload, err := json.Marshal(vnis)
			if err != nil {
				b.Fatal(err)
			}
			run := func(_ context.Context, command string) ([]byte, error) {
				if command == vniCmd {
					return payload, nil
				}
				if command == esCmd {
					return empty, nil
				}
				return nil, fmt.Errorf("unexpected command %s", command)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := collectEVPN(context.Background(), run); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
