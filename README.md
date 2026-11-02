# frr-metrics-exporter

Prometheus exporter for an FRR that runs **outside Kubernetes**, such as a VM or appliance. It
reads FRR through `vtysh` and serves BGP, BFD and EVPN metrics over HTTPS with optional client
certificates.

It is a reference implementation of the series an EVPN gateway needs from FRR, and a standalone
option where frr-k8s's `frr-metrics` cannot be used: it needs in-cluster authentication (see
[frr-k8s#518](https://github.com/metallb/frr-k8s/issues/518) and
[#519](https://github.com/metallb/frr-k8s/pull/519)) and exports no EVPN series. frr-k8s remains
the natural home for these series. Each collector is a small parser over real FRR output
(`testdata/`), so it can be ported there as it is; nothing here depends on frr-k8s.

The series names, types and BGP labels follow frr-k8s's exporter (Apache-2.0, the MetalLB
authors), so dashboards and rules written for it keep working. The `frrk8s_` prefix is kept for
that reason; tell the sources apart with scrape labels.

## Metrics

| Series | Labels | Meaning |
| --- | --- | --- |
| `frrk8s_bgp_session_up` | `peer,vrf` | 1 if Established, 0 in every other state (the state's name is not exported). For an unnumbered peer `peer` is the interface name |
| `frrk8s_bgp_announced_prefixes_total`, `frrk8s_bgp_received_prefixes_total` | `peer,vrf` | Gauges that **sum every address family**, as in frr-k8s |
| `frrk8s_bgp_family_announced_prefixes`, `frrk8s_bgp_family_received_prefixes` | `peer,vrf,afi,safi` | Per family: `ipv4/unicast`, `ipv6/unicast`, `ipv4/vpn`, `l2vpn/evpn`; any other family counts only in the `_total` gauges. A count FRR did not report is absent, never 0 |
| `frrk8s_bgp_{opens,notifications,updates,keepalives}_*`, `route_refresh_sent`, `total_*` | `peer,vrf` | Message counters, per TCP session |
| `frrk8s_bfd_session_up`, `_control_packet_*`, `_echo_packet_*`, `_session_{up,down}_events`, `_zebra_notifications` | `peer,vrf,local,interface,multihop` | frr-k8s's BFD series with FRR's full session identity, so several sessions to one peer stay distinct. `peer` is the address, so it matches the BGP `peer` for numbered peers only |
| `frrk8s_evpn_vni_info` | `vni,vrf,type,interface` | 1 per VNI zebra knows: inventory, not health |
| `frrk8s_evpn_macs`, `_neighbors`, `_remote_vteps` | `vni,vrf` | L2 VNIs only: MACs and ARP/ND entries zebra holds, and known remote VTEPs. A known VTEP is not proof of reachability |
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
  so rotation needs no restart. A bad rotation, including a deleted or emptied CA file, keeps the
  last good configuration, never turns client authentication off, logs once, and sets
  `frrk8s_exporter_tls_config_current` to 0. Alert on that, and on the expiry series.
- Each scrape reads FRR afresh with `show bgp vrf all neighbors json` (one command for every VRF),
  `show bfd peers json` and `show bfd peers counters json`, and `show evpn vni json`. The
  collectors run at once, each with the whole deadline, so a slow one cannot starve the others.
- The deadline is `--scrape-timeout`, lowered to 90% of the scraper's own timeout when Prometheus
  announces it. A hung `vtysh` is killed at the deadline.
- At most four scrapes read FRR at once (two Prometheus replicas and an operator with `curl`); more get `503`. A slot is held
  only while FRR is read, not while the response is written, so a slow client cannot starve others.
- A failed collector never leaves half a result: it emits nothing but its status. Collectors fail
  on malformed output and on BFD data that cannot be represented (two sessions with one identity,
  or one session id with two identities). A BFD session seen in only one of the two reads changed
  between them; its counters are skipped for that scrape. If the exporter itself builds
  inconsistent output (a duplicate series), the scrape fails with `500` rather than serving a subset.
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
It passes on FRR 10.4.3 and 10.6.2 and needs podman, openssl and curl. `make vuln` runs govulncheck (it needs network access).

## Design notes

- `collector/` is the whole FRR side: `Collector`s that turn `vtysh` output into metrics, and the
  `Vtysh` runner. It has no HTTP, TLS or flags, and the layout mirrors frr-k8s's
  `cmd/metrics/collector`, so porting is copying the directory. The root package is the server.

- TLS is plain `crypto/tls` (`tls.go`) rather than the Prometheus exporter-toolkit's web
  configuration, which node-exporter uses. The toolkit would add about 35 modules (JWT, OAuth2,
  systemd, YAML) and a YAML file to do what three flags do here. If you want its format, put the
  exporter on loopback behind a proxy that speaks it.
- Scale: parsing 2000 neighbors (7 MB of JSON, 34,000 series) takes about 0.2 s
  (`go test -bench CollectBGP ./collector`). Each FRR read is capped at 32 MiB, roughly 8,000 neighbors.

## Limits

- Not implemented: EVPN Ethernet segment and DF state (needs a multihoming lab to verify), the
  per-VTEP membership series, BFD RTT, and a certificate revocation list.
- `make build` makes a static binary with Go's own crypto. A FIPS-validated build needs your
  distribution's Go toolchain.
- Building needs Go 1.26 (set by the `golang.org/x` dependencies). Only the FRR versions above are exercised. JSON shapes differ between releases; check new ones
  with `make smoke` (`FRR_IMAGE=...`).
- Where FRR omits a field, the series is omitted, never reported as 0; the `_total` BGP gauges are
  the exception because they sum whatever is present.

## License

Apache-2.0.
