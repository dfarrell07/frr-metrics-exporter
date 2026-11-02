# frr-metrics-exporter

Prometheus exporter for an FRR that runs **outside Kubernetes**, such as a VM or appliance. It
reads FRR through `vtysh` and serves BGP, BFD and EVPN metrics over HTTPS with optional client
certificates.

It is a standalone reference implementation of the FRR series in the EGA metrics plan.
Collectors use real FRR output ([fixtures and provenance](collector/testdata/README.md))
and can be ported independently of the serving code.

Existing BGP series names, types and labels follow frr-k8s's exporter (Apache-2.0, the MetalLB
authors). The `frrk8s_` prefix is kept for compatibility; tell sources apart with scrape labels.
BFD adds `local,interface,multihop` to upstream's `peer,vrf`: migrate joins and expected-session
inventory to the five-label identity rather than merging distinct sessions. This is not a
drop-in replacement for every legacy `frr_exporter` metric; uptime and process/RIB/AS metadata
are not carried over.

## Metrics

| Series | Labels | Meaning |
| --- | --- | --- |
| `frrk8s_bgp_session_up` | `peer,vrf` | 1 if Established, 0 in every other state (the state's name is not exported). For an unnumbered peer `peer` is the interface name |
| `frrk8s_bgp_announced_prefixes_total`, `frrk8s_bgp_received_prefixes_total` | `peer,vrf` | Gauges that **sum every address family**, as in frr-k8s |
| `frrk8s_bgp_family_announced_prefixes`, `frrk8s_bgp_family_received_prefixes` | `peer,vrf,afi,safi` | Per family: `ipv4/unicast`, `ipv6/unicast`, `ipv4/vpn`, `l2vpn/evpn`; any other family counts only in the `_total` gauges. A count FRR did not report is absent, never 0 |
| `frrk8s_bgp_{opens,notifications,updates,keepalives}_*`, `route_refresh_sent`, `total_*` | `peer,vrf` | Message counters, per TCP session |
| `frrk8s_bfd_session_up`, `_control_packet_*`, `_echo_packet_*`, `_session_{up,down}_events`, `_zebra_notifications` | `peer,vrf,local,interface,multihop` | frr-k8s's BFD series with ordinary single-hop/multihop session identity, so several sessions to one peer stay distinct. `peer` is the address, so it matches the BGP `peer` for numbered peers only |
| `frrk8s_evpn_vni_info` | `vni,vrf,type,interface` | 1 per VNI zebra knows: inventory, not health |
| `frrk8s_evpn_macs`, `_neighbors`, `_remote_vteps` | `vni,vrf` | L2 VNIs only: MACs and ARP/ND entries zebra holds, and known remote VTEPs. A known VTEP is not proof of reachability |
| `frrk8s_evpn_remote_vtep_present` | `vni,vrf,vtep` | Gauge 1 for each known remote VTEP of an L2 VNI. An absent list does not invent memberships or change the reported aggregate count |
| `frrk8s_evpn_es_oper_up` | `esi` | Gauge 1/0 for a local Ethernet segment's access-port operational state. Remote-only segments are omitted; this is not forwarding health |
| `frrk8s_evpn_es_df` | `esi` | Gauge 1 for local DF, 0 for local non-DF. Omitted while down, unready, bypassed, waiting for an election, or without an explicit role. Non-DF can be a healthy elected role |
| `frrk8s_scrape_collector_success`, `_duration_seconds` | `collector` | Per collector: 1 if the read and parse were complete. A failed collector emits no other series |
| `frrk8s_exporter_tls_config_current`, `frrk8s_exporter_tls_cert_not_after_timestamp_seconds` | | 0 if the last certificate or CA reload failed and the previous ones are still served; expiry of the server certificate |

The names are kept for compatibility, so `promtool check metrics` flags the two `_total` gauges and
the counters that lack a `_total` suffix.

## Use

```sh
make build
./frr-metrics-exporter \
  --listen 0.0.0.0:9141 \
  --tls-cert-file server.crt --tls-key-file server.key \
  --tls-client-ca-file scraper-ca.crt
```

It must run where `/usr/bin/vtysh` reaches FRR's sockets, as root or in FRR's `frrvty` group: on
the host with the FRR package, or in the FRR container image (the binary is static, so it can be
mounted in or copied there).

A Prometheus scrape job:

```yaml
scrape_configs:
  - job_name: frr
    scheme: https
    tls_config:
      ca_file: server-ca.crt
      cert_file: scraper.crt
      key_file: scraper.key
      server_name: appliance.example.com   # must match the server certificate
    static_configs:
      - targets: ["appliance.example.com:9141"]
```

A throwaway CA with server and scraper certificates (see `hack/smoke.sh` for the same with
`-days 1`); the server certificate needs a SAN matching what the scraper connects to:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -days 365 -subj /CN=frr-ca
for n in server scraper; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $n.key -out $n.csr -subj /CN=$n
  printf 'subjectAltName=DNS:appliance.example.com\nextendedKeyUsage=serverAuth,clientAuth\n' > $n.ext
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $n.crt -days 365 -extfile $n.ext
done
```

| Flag | Meaning |
| --- | --- |
| `--listen` | Default `127.0.0.1:9141`. Any other address needs `--tls-client-ca-file`; the exporter refuses to start otherwise. |
| `--tls-cert-file`, `--tls-key-file` | Required. |
| `--tls-client-ca-file` | Scrapers must present a certificate from this CA (mTLS). |
| `--vtysh` | Default `/usr/bin/vtysh`. |
| `--version` | Print the version and exit. |
| `--collectors` | Default `bgp,bfd,evpn`. Drop one where FRR does not run that daemon: its read fails on every scrape, with `bfdd is not running` in the log and `success 0`. |
| `--scrape-timeout` | Default `8s`: one deadline for all FRR reads in a scrape. Keep it below the scraper's timeout. |

Behavior:

- TLS 1.3 only; `/metrics` is the only path. No Kubernetes or basic authentication. With
  `--tls-client-ca-file`, any certificate from that CA may scrape, so use a CA that issues only
  scraper certificates.
- The certificate, key and client CA are re-read when they change (checked at most once a second),
  so rotation needs no restart. A rejected rotation, including a deleted or emptied CA file, keeps the
  last good configuration, never turns client authentication off, logs once, and sets
  `frrk8s_exporter_tls_config_current` to 0. Alert on that, and on the expiry series.
  New server leaves must be currently valid and permit server authentication. Server certificate
  and client CA files must contain complete certificate PEM blocks, with whitespace or `#` comments between them;
  one valid root does not excuse another damaged block in the bundle.
- Client-CA changes apply at TLS handshakes. A cached TLS session is rechecked, but an existing
  authenticated connection keeps its access until closed; an active keep-alive connection can
  persist indefinitely. Restart the exporter to terminate existing connections when removing
  trust. Agree the deployment's revocation latency; file reload alone does not revoke them.
- Each scrape reads FRR afresh with `show bgp vrf all neighbors json` (one command for every VRF),
  `show bfd peers json` and `show bfd peers counters json`, and `show evpn vni json` plus
  `show evpn es detail json`. The
  collectors run at once, each with the whole deadline. Each `vtysh` connects only to the
  command's daemon (`bgpd`, `bfdd` or `zebra`), so a stuck daemon cannot block unrelated reads
  during CLI initialization.
- The deadline is `--scrape-timeout`, lowered to 90% of the scraper's own timeout when Prometheus
  announces it. A hung `vtysh` is killed at the deadline.
  Use the direct executable or an `exec` wrapper: cancellation kills that process and bounds
  inherited-pipe waiting, but does not manage descendants spawned by other wrappers.
- At most four scrapes read FRR at once; read slots are released before writing. At most eight
  handlers gather or write responses, bounding snapshots retained by slow readers. Requests
  beyond either limit get `503` before reading FRR. Headers and request bodies have a three-second
  read timeout; write deadlines alone cannot bound draining an incomplete request body.
- A failed collector never leaves half a result: it emits nothing but its status. Collectors fail
  on malformed output, including null replies, missing state or inventory identity, and invalid
  counts. BFD joins the two reads by session ID and cross-checks the label identity; duplicate
  IDs or identities fail. A session seen in only one read, or recreated between reads, fails the
  whole BFD collector for that scrape. Independent collectors still report. If the exporter itself builds
  inconsistent output (a duplicate series), the scrape fails with `500` rather than serving a subset.
- EVPN uses two bulk reads, with one complete result: a failed ES read drops VNI and membership
  metrics too. VTEP addresses and ESIs are normalized and duplicates rejected. A supplied VTEP
  list must agree with its count when both are reported. Local ES operational state uses the
  explicit flags array; a local access port without local flags fails collection. Valid implicit
  MAC-only ES entries have no ownership flags or access port and emit no local state. FRR can print `df` on an unready or
  bypassed segment, so the DF series also requires `readyForBgp`, `operUp`, no `bypass`, and
  no pending `dfDelayTimer`. No role is inferred from a missing flag or a remote segment.
- `SIGTERM` or `SIGINT` drains in-flight scrapes, cancels any still running after 5 seconds, waits
  for their `vtysh` processes to die, and exits.
- **Alert on `frrk8s_scrape_collector_success == 0` and on absent series, as well as on `up`.** If
  FRR is down the exporter still answers `200`.

## Verification

`make check` runs gofmt, vet and the race-enabled tests: parsers against real FRR 10.4.3 output
(`collector/testdata/`, including peers in a VRF, IPv6 and unnumbered peers, down peers and a
multihop BFD session), the edge cases
above, mTLS and rotation, TLS reload health, the deadline and the scraper's timeout, the scrape
slots, the `vtysh` runner (its output limit and kill-on-deadline), and shutdown cancelling a hung
scrape. `make smoke` runs the exporter against two real FRR containers (BGP for IPv4 and
EVPN, BFD, an L2 VNI with a learned MAC, an L3 VNI, and a peer that does not exist) and checks the
series, that every collector succeeds, and that a scrape without a client certificate is refused.
The exporters run as the image's `frr` user. The test adds LACP access bonds and a shared ESI,
checks both peers' DF/non-DF metrics, changes preference to elect the other PE, and checks
bypass, link down, remote-only state and VNI deletion. Each PE uses its own virtual CE bond;
this verifies control-plane observations, not shared-CE forwarding or appliance HA.
The test also freezes each daemon in turn and checks collector isolation, a three-second client
budget, no surviving `vtysh`, and recovery. It needs podman, openssl, curl and Linux bonding
(802.3ad). `SMOKE_DUMP=file` keeps the healthy scrape before fault injection. `make vuln` runs
govulncheck (network access required).

The full smoke passes with upstream FRR 10.4.3/10.6.2 and with the EGA-pinned Red Hat payload:

```sh
FRR_IMAGE=registry.redhat.io/openshift4/frr-rhel9@sha256:82fd7cc0123f6286bad46231a9939799ae79c30b9369047d2ffd109dacefa76e make smoke
```

That image contains RHEL 9.8 `frr10-10.4.3-3.el9_8.2`; the exporter runs as its `frr` user.
These are local rootless-container checks on a Fedora host, including the Red Hat package;
they do not qualify the RHEL 10 appliance, its SELinux policy, architectures or FIPS build.

Complete scrape cost is measured with `make build && python3 hack/load.py` (Linux, Python 3,
openssl). It runs the actual binary restricted to two logical CPUs with `GOMAXPROCS=2`, subprocess
fixture replay, mTLS, registry gathering, text/gzip encoding and full response validation. The load is
2,000 BGP neighbors, 64 L2 VNIs × 256 VTEPs, one BFD session and one local ES: 50,658 `frrk8s_*`
samples plus Go/process metrics. Each scraper requests once per second, ten times per phase; stalled
clients request 4 KiB socket receive buffers and stop after response headers. This measures exporter cost;
real FRR query time and remote network latency still need qualification at the declared scale.

Measured 2026-11-02 on an i7-8665U Linux amd64 host (16 GiB RAM, Go 1.26.10), restricted to two
logical CPUs; memory was not constrained. CPU includes exporter and replay subprocess time.
RSS peaks are the exporter's cumulative kernel high-water mark, not Go heap allocation counts.

| Load | CPU seconds / 20 scrapes | Maximum response | Peak RSS |
| --- | ---: | ---: | ---: |
| Two scrapers, plain text | 10.20 | 0.61 s | 176 MiB |
| Two scrapers, gzip | 10.71 | 0.61 s | 179 MiB |
| Two gzip scrapers plus two stalled readers | 11.36 | 0.68 s | 284 MiB |
| Two gzip scrapers after recovery | 10.85 | 0.63 s | 389 MiB |

Plain responses were 3.82 MB, gzip 156 kB. With all eight response slots stalled, a ninth request
returned `503` without CLI work; a complete scrape recovered 10.2 seconds after rejection. Peak
RSS reached 389 MiB, then fell to 157 MiB during the post-recovery scrape phase and stayed there
through five idle seconds. Write deadlines include five seconds beyond the configured scrape
timeout; TLS closure can add up to five more seconds. Admission bounds concurrency, not a fixed
memory allowance.

An additional live test used the pinned Red Hat image: 2,000 BGP neighbors (one Established),
64 L2 VNIs with one VTEP each, one L3 VNI and one BFD session, without local ESs. With the
exporter restricted to two logical CPUs and its router container limited to 1 GiB, two gzip scrapers
completed 20 scrapes in 10.27 seconds (maximum 1.26 s); with two stalled readers, 10.00 seconds
(maximum 0.71 s). Exporter/CLI CPU was 9.35/8.08 seconds per phase, peak exporter RSS 108 MiB.
Whole-container CPU, including FRR JSON generation, was 12.67/11.05 seconds; cgroup memory
peaked at 478 MiB, including file cache. After stalled clients disconnected, two complete scrapes
took 0.86 seconds. Live FRR at 256 VTEPs per VNI remains unqualified.

## Design notes

- `collector/` is the whole FRR side: `Collector`s that turn `vtysh` output into metrics, and the
  `Vtysh` runner. It has no HTTP, TLS or flags, and the layout mirrors frr-k8s's
  `cmd/metrics/collector`; it can be ported independently of this server.

- TLS uses `crypto/tls` (`tls.go`), with certificate and CA files supplied through flags.
- Each FRR reply is capped at 32 MiB; this bounds input, not the parsed snapshot or encoded response.
- Membership adds one series per observed L2 VNI/VTEP pair, not per BGP peer: a relay can
  advertise many VTEPs. ES metrics add at most two series per local ESI. No per-MAC, per-IP
  neighbor or route labels are exported.

## Limits

- This is a standalone candidate and a source of tested collectors, not a qualified appliance
  payload. CORENET-7504/7505 currently require the frr-k8s binary; shipping a replacement needs
  amended criteria and agreed build, update and security ownership. Rootful RHEL 10 with SELinux,
  the selected release image and platforms, socket sharing, appliance lifecycle and the remote
  scrape path remain to be qualified. Local container tests do not establish those properties.
- All named FRR series in the EGA planning table are implemented. The rest of CORENET-7504
  needs other sources: node-exporter for appliance/interface/bandwidth observations,
  CloudWatch for AWS DX/VPN state, and an agreed continuous probe for forwarding/latency.
  MAC occupancy is not a learning-event rate; BGP UPDATE counts are not changed-route counts.
  Per-VTEP membership is optional follow-on coverage enabled in this reference; its shipping
  default and expected-specific alert policy remain unselected.
- BFD RTT remains unexported: FRR 10.4.3's echo-window fields report zero without samples,
  supply no sample age, and its CLI caps the minimum at 1000 microseconds. They cannot establish
  general BFD or transport latency ([FRR's CLI producer](https://github.com/FRRouting/frr/blob/frr-10.4.3/bfdd/bfdd_vty.c)). The plan leaves the latency source undecided. Certificate
  revocation lists are also not implemented.
- BFD supports ordinary single-hop and multihop sessions. Named/SBFD modes are rejected until
  their identity contract is qualified; a lone named path must not satisfy ordinary BFD health.
  Any sessions that collide on the current labels also fail collection.
- `make build` makes a static binary with Go's own crypto. A FIPS-validated build needs your
  distribution's Go toolchain.
- Building needs Go 1.26 (set by the `golang.org/x` dependencies). Only the FRR versions above are exercised. JSON shapes differ between releases; check new ones
  with `make smoke` (`FRR_IMAGE=...`).
- Where FRR omits a field, the series is omitted, never reported as 0; the `_total` BGP gauges are
  the exception because they sum whatever is present.

## License

Apache-2.0.
