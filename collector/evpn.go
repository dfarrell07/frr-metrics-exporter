// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	evpnVNIInfo     = desc("evpn_vni_info", "Observed EVPN VNI inventory (always 1); not expected inventory or health", "vni", "vrf", "type", "interface")
	evpnMACs        = desc("evpn_macs", "MAC addresses zebra holds for the L2 VNI, local and remote", "vni", "vrf")
	evpnNeighbors   = desc("evpn_neighbors", "ARP and ND entries zebra holds for the L2 VNI", "vni", "vrf")
	evpnRemoteVTEPs = desc("evpn_remote_vteps", "Remote VTEPs known for the L2 VNI; a known VTEP is not proof of reachability", "vni", "vrf")
)

type evpnVNI struct {
	Type      string   `json:"type"`
	VxlanIf   string   `json:"vxlanIf"`
	TenantVRF string   `json:"tenantVrf"`
	MACs      *float64 `json:"numMacs"`
	ArpND     *float64 `json:"numArpNd"`
	// A number for L2 VNIs and the string "n/a" for L3 VNIs.
	RemoteVTEPs any `json:"numRemoteVteps"`
}

// collectEVPN reads zebra's VNI summary. With no VNIs FRR returns {}, which is
// a successful read with no series. Only L2 VNIs get occupancy series: an L3
// VNI reports "n/a" remote VTEPs and its counts are not L2 occupancy.
func collectEVPN(ctx context.Context, run Runner) ([]prometheus.Metric, error) {
	out, err := run(ctx, "show evpn vni json")
	if err != nil {
		return nil, err
	}
	var vnis map[string]evpnVNI
	if err := json.Unmarshal(out, &vnis); err != nil {
		return nil, fmt.Errorf("parsing EVPN VNIs: %w", err)
	}
	var ms []prometheus.Metric
	for vni, v := range vnis {
		ms = append(ms, prometheus.MustNewConstMetric(evpnVNIInfo, prometheus.GaugeValue, 1, vni, v.TenantVRF, v.Type, v.VxlanIf))
		if v.Type != "L2" {
			continue
		}
		if v.MACs != nil {
			ms = append(ms, prometheus.MustNewConstMetric(evpnMACs, prometheus.GaugeValue, *v.MACs, vni, v.TenantVRF))
		}
		if v.ArpND != nil {
			ms = append(ms, prometheus.MustNewConstMetric(evpnNeighbors, prometheus.GaugeValue, *v.ArpND, vni, v.TenantVRF))
		}
		if n, ok := v.RemoteVTEPs.(float64); ok {
			ms = append(ms, prometheus.MustNewConstMetric(evpnRemoteVTEPs, prometheus.GaugeValue, n, vni, v.TenantVRF))
		}
	}
	return ms, nil
}
