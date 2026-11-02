// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// Series names, types and labels for BGP follow the frr-k8s exporter, so
// dashboards and rules written for it keep working.

var (
	peerVRF = []string{"peer", "vrf"}

	bgpSessionUp = desc("bgp_session_up", "BGP session state (1 is up, 0 is down)", peerVRF...)
	// The two _total series are gauges that sum every address family. Use the
	// per-family series below to tell families apart.
	bgpAnnounced = desc("bgp_announced_prefixes_total", "Number of prefixes currently being advertised on the BGP session, all address families", peerVRF...)
	bgpReceived  = desc("bgp_received_prefixes_total", "Number of prefixes currently being received on the BGP session, all address families", peerVRF...)

	bgpFamilyAnnounced = desc("bgp_family_announced_prefixes", "Number of prefixes currently being advertised on the BGP session for one address family", "peer", "vrf", "afi", "safi")
	bgpFamilyReceived  = desc("bgp_family_received_prefixes", "Number of prefixes currently being received on the BGP session for one address family", "peer", "vrf", "afi", "safi")

	// Message counters belong to the TCP session, so they stay per peer.
	bgpMessages = []struct {
		desc *prometheus.Desc
		key  string
	}{
		{desc("bgp_opens_sent", "Number of BGP open messages sent", peerVRF...), "opensSent"},
		{desc("bgp_opens_received", "Number of BGP open messages received", peerVRF...), "opensRecv"},
		{desc("bgp_notifications_sent", "Number of BGP notification messages sent", peerVRF...), "notificationsSent"},
		{desc("bgp_updates_total", "Number of BGP UPDATE messages sent", peerVRF...), "updatesSent"},
		{desc("bgp_updates_total_received", "Number of BGP UPDATE messages received", peerVRF...), "updatesRecv"},
		{desc("bgp_keepalives_sent", "Number of BGP keepalive messages sent", peerVRF...), "keepalivesSent"},
		{desc("bgp_keepalives_received", "Number of BGP keepalive messages received", peerVRF...), "keepalivesRecv"},
		{desc("bgp_route_refresh_sent", "Number of BGP route refresh messages sent", peerVRF...), "routeRefreshSent"},
		{desc("bgp_total_sent", "Number of total BGP messages sent", peerVRF...), "totalSent"},
		{desc("bgp_total_received", "Number of total BGP messages received", peerVRF...), "totalRecv"},
	}
)

// bgpFamilies maps the family keys FRR 10.4.3 uses to afi and safi labels.
// Other keys count only in the _total gauges.
var bgpFamilies = map[string][2]string{
	"ipv4Unicast": {"ipv4", "unicast"},
	"ipv6Unicast": {"ipv6", "unicast"},
	"ipv4Vpn":     {"ipv4", "vpn"},
	"l2VpnEvpn":   {"l2vpn", "evpn"},
}

type bgpNeighbor struct {
	State    string             `json:"bgpState"`
	Stats    map[string]*uint64 `json:"messageStats"`
	Families map[string]struct {
		// Pointers: FRR omits sentPrefixCounter for a family with no update
		// subgroup, and a missing count must not read as zero.
		Sent     *uint64 `json:"sentPrefixCounter"`
		Accepted *uint64 `json:"acceptedPrefixCounter"`
	} `json:"addressFamilyInfo"`
}

// collectBGP reads every neighbor in every VRF with one command. FRR keys the
// reply by VRF and puts the peers beside two bookkeeping entries.
func collectBGP(ctx context.Context, run Runner) ([]prometheus.Metric, error) {
	out, err := run(ctx, "show bgp vrf all neighbors json")
	if err != nil {
		return nil, err
	}
	var vrfs map[string]map[string]json.RawMessage
	if err := json.Unmarshal(out, &vrfs); err != nil {
		return nil, fmt.Errorf("parsing BGP neighbors: %w", err)
	}
	if vrfs == nil {
		return nil, fmt.Errorf("BGP neighbors must be an object, not null")
	}
	var ms []prometheus.Metric
	for vrf, entries := range vrfs {
		if vrf == "" || entries == nil {
			return nil, fmt.Errorf("invalid BGP VRF %q", vrf)
		}
		for peer, raw := range entries {
			// These bookkeeping names can also be unnumbered peer interfaces.
			// FRR uses scalar metadata and object-valued neighbors in one map.
			if peer == "vrfId" {
				var id *int64 // FRR uses -1 for a configured VRF missing from the kernel.
				if json.Unmarshal(raw, &id) == nil && id != nil {
					continue
				}
			}
			if peer == "vrfName" {
				var name *string
				if json.Unmarshal(raw, &name) == nil && name != nil {
					continue
				}
			}
			var n bgpNeighbor
			if err := json.Unmarshal(raw, &n); err != nil {
				return nil, fmt.Errorf("parsing BGP neighbor %s in VRF %s: %w", peer, vrf, err)
			}
			if peer == "" || n.State == "" {
				return nil, fmt.Errorf("BGP neighbor %q in VRF %s has no identity or state", peer, vrf)
			}
			ms = append(ms, n.metrics(peer, vrf)...)
		}
	}
	return ms, nil
}

func (n bgpNeighbor) metrics(peer, vrf string) []prometheus.Metric {
	up := 0.0
	if n.State == "Established" {
		up = 1
	}
	var announced, received float64
	ms := []prometheus.Metric{prometheus.MustNewConstMetric(bgpSessionUp, prometheus.GaugeValue, up, peer, vrf)}
	for key, f := range n.Families {
		if f.Sent != nil {
			announced += float64(*f.Sent)
		}
		if f.Accepted != nil {
			received += float64(*f.Accepted)
		}
		if fam, known := bgpFamilies[key]; known {
			if f.Sent != nil {
				ms = append(ms, prometheus.MustNewConstMetric(bgpFamilyAnnounced, prometheus.GaugeValue, float64(*f.Sent), peer, vrf, fam[0], fam[1]))
			}
			if f.Accepted != nil {
				ms = append(ms, prometheus.MustNewConstMetric(bgpFamilyReceived, prometheus.GaugeValue, float64(*f.Accepted), peer, vrf, fam[0], fam[1]))
			}
		}
	}
	ms = append(ms,
		prometheus.MustNewConstMetric(bgpAnnounced, prometheus.GaugeValue, announced, peer, vrf),
		prometheus.MustNewConstMetric(bgpReceived, prometheus.GaugeValue, received, peer, vrf))
	for _, m := range bgpMessages {
		if v := n.Stats[m.key]; v != nil {
			ms = append(ms, prometheus.MustNewConstMetric(m.desc, prometheus.CounterValue, float64(*v), peer, vrf))
		}
	}
	return ms
}
