// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	evpnVNIInfo     = desc("evpn_vni_info", "Observed EVPN VNI inventory (always 1); not expected inventory or health", "vni", "vrf", "type", "interface")
	evpnMACs        = desc("evpn_macs", "MAC addresses zebra holds for the L2 VNI, local and remote", "vni", "vrf")
	evpnNeighbors   = desc("evpn_neighbors", "ARP and ND entries zebra holds for the L2 VNI", "vni", "vrf")
	evpnRemoteVTEPs = desc("evpn_remote_vteps", "Remote VTEPs known for the L2 VNI; a known VTEP is not proof of reachability", "vni", "vrf")
	evpnVTEPPresent = desc("evpn_remote_vtep_present", "Remote VTEP known for the L2 VNI (always 1); membership, not reachability", "vni", "vrf", "vtep")
	evpnESOperUp    = desc("evpn_es_oper_up", "Local Ethernet segment access-port operational state (1 is up, 0 is down); not forwarding health", "esi")
	evpnESDF        = desc("evpn_es_df", "Local Ethernet segment DF role (1 is DF, 0 is non-DF); only when ready, operational, not bypassed and no election delay is pending", "esi")
)

type evpnVNI struct {
	VNI       uint32  `json:"vni"`
	Type      string  `json:"type"`
	VxlanIf   string  `json:"vxlanIf"`
	TenantVRF string  `json:"tenantVrf"`
	MACs      *uint64 `json:"numMacs"`
	ArpND     *uint64 `json:"numArpNd"`
	// A number for L2 VNIs and the string "n/a" for L3 VNIs.
	RemoteVTEPs json.RawMessage `json:"numRemoteVteps"`
	VTEPs       []string        `json:"remoteVteps"`
}

// collectEVPN reads zebra's VNI summary and Ethernet segments as one result.
// An empty VNI inventory does not imply there are no local Ethernet segments.
// Only L2 VNIs get occupancy: an L3 VNI reports "n/a" remote VTEPs and its
// counts are not L2 occupancy.
func collectEVPN(ctx context.Context, run Runner) ([]prometheus.Metric, error) {
	out, err := run(ctx, "show evpn vni json")
	if err != nil {
		return nil, err
	}
	var vnis map[string]evpnVNI
	if err := json.Unmarshal(out, &vnis); err != nil {
		return nil, fmt.Errorf("parsing EVPN VNIs: %w", err)
	}
	if vnis == nil {
		return nil, fmt.Errorf("EVPN VNIs must be an object, not null")
	}
	var ms []prometheus.Metric
	for vni, v := range vnis {
		if v.VNI == 0 || v.VNI > 16777215 || strconv.FormatUint(uint64(v.VNI), 10) != vni ||
			(v.Type != "L2" && v.Type != "L3") || v.TenantVRF == "" || v.VxlanIf == "" {
			return nil, fmt.Errorf("invalid EVPN VNI %q: identity, type, VRF and interface are required", vni)
		}
		ms = append(ms, prometheus.MustNewConstMetric(evpnVNIInfo, prometheus.GaugeValue, 1, vni, v.TenantVRF, v.Type, v.VxlanIf))
		if v.Type != "L2" {
			continue
		}
		if v.MACs != nil {
			ms = append(ms, prometheus.MustNewConstMetric(evpnMACs, prometheus.GaugeValue, float64(*v.MACs), vni, v.TenantVRF))
		}
		if v.ArpND != nil {
			ms = append(ms, prometheus.MustNewConstMetric(evpnNeighbors, prometheus.GaugeValue, float64(*v.ArpND), vni, v.TenantVRF))
		}
		var remote *uint64
		if len(v.RemoteVTEPs) > 0 {
			if err := json.Unmarshal(v.RemoteVTEPs, &remote); err != nil {
				return nil, fmt.Errorf("parsing remote VTEP count for L2 VNI %s: %w", vni, err)
			}
		}
		if remote != nil {
			ms = append(ms, prometheus.MustNewConstMetric(evpnRemoteVTEPs, prometheus.GaugeValue, float64(*remote), vni, v.TenantVRF))
		}
		if v.VTEPs != nil && remote != nil && uint64(len(v.VTEPs)) != *remote {
			return nil, fmt.Errorf("VNI %s remote VTEP list and count disagree", vni)
		}
		seen := make(map[netip.Addr]bool, len(v.VTEPs))
		for _, ip := range v.VTEPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil || addr.Zone() != "" || seen[addr] {
				return nil, fmt.Errorf("invalid or duplicate remote VTEP %q for VNI %s", ip, vni)
			}
			seen[addr] = true
			ms = append(ms, prometheus.MustNewConstMetric(evpnVTEPPresent, prometheus.GaugeValue, 1, vni, v.TenantVRF, addr.String()))
		}
	}
	es, err := collectEVPNES(ctx, run)
	if err != nil {
		return nil, err
	}
	return append(ms, es...), nil
}

type evpnES struct {
	ESI          string          `json:"esi"`
	AccessPort   *string         `json:"accessPort"`
	Flags        []string        `json:"flags"`
	DFDelayTimer json.RawMessage `json:"dfDelayTimer"`
}

// collectEVPNES uses the detail command: the summary omits operational and DF
// flags. The flags array is a bitset, so absent operUp means down only when the
// array is present and explicitly identifies a local segment.
func collectEVPNES(ctx context.Context, run Runner) ([]prometheus.Metric, error) {
	out, err := run(ctx, "show evpn es detail json")
	if err != nil {
		return nil, err
	}
	var segments []evpnES
	if err := json.Unmarshal(out, &segments); err != nil {
		return nil, fmt.Errorf("parsing EVPN Ethernet segments: %w", err)
	}
	if segments == nil {
		return nil, fmt.Errorf("EVPN Ethernet segments must be an array, not null")
	}
	seen := make(map[string]bool, len(segments))
	var ms []prometheus.Metric
	for _, s := range segments {
		// FRR prints a 10-octet ESI; normalize case before detecting duplicates.
		raw, err := hex.DecodeString(strings.ReplaceAll(s.ESI, ":", ""))
		esi := strings.ToLower(s.ESI)
		if err != nil || len(raw) != 10 || esi != net.HardwareAddr(raw).String() ||
			esi == "00:00:00:00:00:00:00:00:00:00" || seen[esi] {
			return nil, fmt.Errorf("invalid or duplicate Ethernet segment ID %q", s.ESI)
		}
		seen[esi] = true
		has := func(flag string) bool { return slices.Contains(s.Flags, flag) }
		if has("") || (has("df") && has("nonDF")) ||
			(s.AccessPort != nil && (*s.AccessPort == "" || !has("local"))) {
			return nil, fmt.Errorf("invalid flags for Ethernet segment %s", esi)
		}
		if len(s.DFDelayTimer) != 0 {
			var timer string
			if err := json.Unmarshal(s.DFDelayTimer, &timer); err != nil || timer == "" {
				return nil, fmt.Errorf("invalid DF delay timer for Ethernet segment %s", esi)
			}
		}
		if !has("local") {
			// An implicit MAC-only ES has neither owner flag nor access port.
			// It is valid inventory, but supplies no local operational state.
			continue
		}
		up := 0.0
		if has("operUp") {
			up = 1
		}
		ms = append(ms, prometheus.MustNewConstMetric(evpnESOperUp, prometheus.GaugeValue, up, esi))
		// FRR can print df even when unready or bypassed. Neither is an
		// elected forwarding role. A down port's nonDF is also inapplicable.
		if up == 0 || !has("readyForBgp") || has("bypass") || len(s.DFDelayTimer) != 0 {
			continue
		}
		if has("df") || has("nonDF") {
			df := 0.0
			if has("df") {
				df = 1
			}
			ms = append(ms, prometheus.MustNewConstMetric(evpnESDF, prometheus.GaugeValue, df, esi))
		}
	}
	return ms, nil
}
