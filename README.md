# frr-metrics-exporter

Prometheus exporter for FRR running **outside Kubernetes**, on a host or in a container. It reads
BGP, BFD and EVPN through `vtysh` and serves `/metrics` over HTTPS with optional mutual TLS
(mTLS). This is a standalone reference implementation and source of portable collectors;
appliance delivery and qualification remain open.

## Quickstart

Building requires Go 1.26 and make. Running requires FRR, `/usr/bin/vtysh`, access to FRR's sockets,
and root or membership in FRR's `frrvty` group. The static binary can run beside FRR or inside its
container; copying the binary alone does not supply those dependencies.

```sh
make build
```

Use managed certificates for deployment. For a local demonstration, the following creates one
CA and certificates for both exporter and scraper. Replace `appliance.example.com` consistently
with the exporter's DNS name; its certificate SAN must match the scraper's connection name.
Only the scraper needs `scraper.key`; keep the CA private key out of the running exporter.
Each account must be able to read its certificate, key and CA files. Restrict private-key access
and file replacement to trusted accounts.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -days 365 -subj /CN=frr-ca
for n in server scraper; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $n.key -out $n.csr -subj /CN=$n
  printf 'subjectAltName=DNS:appliance.example.com\nextendedKeyUsage=serverAuth,clientAuth\n' > $n.ext
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $n.crt -days 365 -extfile $n.ext
done
./frr-metrics-exporter --listen 0.0.0.0:9141 \
  --tls-cert-file server.crt --tls-key-file server.key --tls-client-ca-file ca.crt
```

From a separate shell, with the scraper's files:

```sh
curl --cacert ca.crt --cert scraper.crt --key scraper.key \
  https://appliance.example.com:9141/metrics
```

A Prometheus scrape job (certificate paths are local to Prometheus):

```yaml
scrape_configs:
  - job_name: frr
    scheme: https
    scrape_timeout: 10s
    tls_config:
      ca_file: ca.crt
      cert_file: scraper.crt
      key_file: scraper.key
      server_name: appliance.example.com
    static_configs:
      - targets: ["appliance.example.com:9141"]
```

| Flag | Default / behavior |
| --- | --- |
| `--listen` | `127.0.0.1:9141`; non-loopback listeners require a client CA. |
| `--tls-cert-file`, `--tls-key-file` | Required server certificate and private key. |
| `--tls-client-ca-file` | Optional on loopback; otherwise required. Enables client-certificate verification. |
| `--vtysh` | `/usr/bin/vtysh`. |
| `--collectors` | `bgp,bfd,evpn`; omit a collector when its FRR daemon is unavailable. |
| `--scrape-timeout` | `8s`; positive deadline for FRR collection. Keep below the scraper's timeout. |
| `--version` | Print build version and exit. |

## Metric contract

Existing BGP names, types and labels follow frr-k8s's exporter. BFD expands upstream's `peer,vrf`
identity with `local,interface,multihop`: update joins and expected-session inventory. Use target
labels to distinguish sources. This does not replace every legacy `frr_exporter` series:
FRR uptime and process/RIB/AS metadata are not carried over.

All names below start with **`frrk8s_`**; braces denote literal alternatives. Unreported numeric counts
produce no sample, never an invented zero. The BGP aggregate prefix gauges are the exception:
they sum present counts across all families, including unmapped families, and emit 0 if none are reported.

| Series suffix | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `bgp_session_up` | Gauge | `peer,vrf` | Established = 1, every other state = 0. An unnumbered peer uses its interface name. |
| `bgp_{announced,received}_prefixes_total` | Gauge | `peer,vrf` | Prefixes summed across all address families. |
| `bgp_family_{announced,received}_prefixes` | Gauge | `peer,vrf,afi,safi` | Per-family counts for `ipv4/unicast`, `ipv6/unicast`, `ipv4/vpn`, `l2vpn/evpn`. |
| `bgp_opens_{sent,received}`, `bgp_notifications_sent`, `bgp_updates_{total,total_received}`, `bgp_keepalives_{sent,received}`, `bgp_route_refresh_sent`, `bgp_total_{sent,received}` | Counter | `peer,vrf` | BGP messages; UPDATE activity is a churn proxy, not changed-route counts. |
| `bfd_session_up` | Gauge | `peer,vrf,local,interface,multihop` | Ordinary single-hop/multihop session: up = 1, otherwise 0. `peer` is an address, unlike unnumbered BGP. |
| `bfd_{control,echo}_packet_{input,output}`, `bfd_session_{up,down}_events`, `bfd_zebra_notifications` | Counter | `peer,vrf,local,interface,multihop` | Packet, session-event and notification counts. |
| `evpn_vni_info` | Gauge | `vni,vrf,type,interface` | 1 per observed VNI; inventory, not health. |
| `evpn_{macs,neighbors,remote_vteps}` | Gauge | `vni,vrf` | L2-only MAC/ARP-ND occupancy and known VTEPs; not learning-event rates or reachability. |
| `evpn_remote_vtep_present` | Gauge | `vni,vrf,vtep` | 1 per observed L2 membership. A missing list invents no members. |
| `evpn_es_oper_up` | Gauge | `esi` | Local access-port state, 1/0; remote-only segments omitted. Not forwarding health. |
| `evpn_es_df` | Gauge | `esi` | Applicable local role: DF = 1, non-DF = 0. Omitted while down, unready, bypassed, pending election or without an explicit role. Non-DF can be healthy. |
| `scrape_collector_{success,duration_seconds}` | Gauge | `collector` | Success = 1 for complete collection, otherwise 0; duration is elapsed seconds. |
| `exporter_tls_config_current` | Gauge | None | 1 when served configuration matches the files; 0 after a rejected reload. |
| `exporter_tls_cert_not_after_timestamp_seconds` | Gauge | None | Served server certificate's expiry, as Unix seconds. |

Compatibility names mean `promtool check metrics` flags the two prefix `_total` gauges and
counters without a `_total` suffix. Membership adds one series per L2 VNI/VTEP pair; ES adds at
most two per local ESI. No per-MAC, per-IP-neighbor or per-route series are exported.

## Access and failure behavior

TLS 1.3 is required. There is no Kubernetes or basic authentication. With a client CA configured,
any valid client certificate from that CA may scrape; use a CA dedicated to scrapers. Without
mTLS, listen on loopback, for example behind a separately authenticated proxy.

Certificates, keys and client CAs are checked at most once a second, on handshakes or scrapes.
Server leaves must be currently valid and permit server authentication. Certificate files accept
LF/CRLF PEM and `#` comments; every block must parse. Invalid startup files prevent serving.
A rejected rotation keeps the last good configuration, preserves authentication, logs the failure
and sets `frrk8s_exporter_tls_config_current` to 0. Alert on reload health and certificate expiry.
CA changes apply to new TLS connections, including resumed sessions. Existing authenticated
connections keep access until closed; restart the exporter for immediate removal of their trust.
Certificate revocation lists are not supported.

Every scrape collects afresh; collectors run concurrently against their own FRR daemons. A
malformed or incomplete result discards that collector's data, retaining only success/duration
gauges; independent collectors still report. BFD's two reads must match by session ID and full
identity, so recreation between reads fails BFD collection. Named/SBFD modes are rejected until
their identity is qualified. EVPN VNI and ES reads form one result: an ES failure drops VNI metrics too.
Inconsistent exporter output fails the entire scrape with `500`.

**HTTP `200` and Prometheus `up` do not prove FRR health.** Alert on collector failure and missing
expected objects/measurements as well as scrape failure. Optional fields and inapplicable DF roles
can legitimately be absent; interpret absence against configuration and collector status.

Collection uses the configured deadline, reduced to 90% of Prometheus's announced timeout when
smaller. A hung `vtysh` is killed. Use its direct executable or an `exec` wrapper; cancellation does
not manage arbitrary wrapper descendants. Each reply is capped at 32 MiB, which bounds input,
not total memory or supported scale.

At most four scrapes read FRR simultaneously and eight handlers gather/write responses.
Excess requests receive `503` before CLI work. Headers/bodies have a three-second read timeout;
the write budget is the configured scrape timeout plus five seconds. TLS closure can add five
more seconds. Admission bounds concurrency, not a fixed memory allowance.
`SIGTERM`/`SIGINT` allow five seconds to drain, then cancel remaining reads and wait for their
`vtysh` processes to terminate before exit.

## Verification and qualification

GitHub Actions runs `make check` and `make build`; smoke, load and vulnerability checks remain manual.

| Command | Coverage / prerequisites |
| --- | --- |
| `make check` | gofmt, vet and race-enabled parser/server tests, using [real fixtures and provenance](collector/testdata/README.md). |
| `make build` | Static binary using Go's crypto. |
| `make vuln` | govulncheck; needs network access. |
| `make smoke` | Two real FRR containers: BGP/BFD/EVPN, DF transitions, mTLS and daemon-hang recovery; needs podman, openssl, curl and Linux bonding. |
| `make build && python3 hack/load.py` | Full binary/subprocess/mTLS/text/gzip replay with two scrapers, stalled readers, CPU/RSS and recovery; needs Linux, Python 3 and openssl. |

Upstream FRR 10.4.3/10.6.2 smoke runs passed. The pinned Red Hat payload was rechecked at
`c8a1144`, running the exporter as its `frr` user:

```sh
FRR_IMAGE=registry.redhat.io/openshift4/frr-rhel9@sha256:82fd7cc0123f6286bad46231a9939799ae79c30b9369047d2ffd109dacefa76e make smoke
```

It contains RHEL 9.8 `frr10-10.4.3-3.el9_8.2`. These are rootless-container checks on Fedora,
not appliance qualification. `SMOKE_DUMP=file` saves the healthy scrape. Scripts are the source
for test mechanics; captures and generated scale data are distinguished in fixture provenance.

Measured on 2026-11-02, i7-8665U Linux amd64, 16 GiB RAM, Go 1.26.10; exporter restricted to
two logical CPUs. Response maxima below describe these runs, not latency guarantees.

| Evidence | Scale | Result |
| --- | --- | --- |
| Fixture replay, `c8a1144` | 2,000 BGP peers, 64 L2 VNIs × 256 VTEPs, one BFD session/local ES; 50,658 `frrk8s_*` samples plus Go/process metrics | Two gzip scrapers: 20 scrapes/10 s, 10.64 CPU s, maximum 0.67 s; with two stalled readers, maximum 0.68 s. Plain/gzip bodies: 3.82 MB/156 kB. |
| Replay overload/recovery, same revision | Eight stalled responses; ninth rejected without CLI work | Recovery 10.5 s; peak RSS 362 MiB, then 160 MiB after recovery/idle. |
| Live pinned Red Hat FRR, `26d27f7` | 2,000 neighbors (one Established), 64 L2 VNIs × one VTEP, one L3 VNI/BFD session; no local ES | Two gzip scrapers: maximum 1.26 s, or 0.71 s with two stalled readers. Exporter RSS peak 108 MiB; whole-container memory peak 478 MiB under a 1 GiB limit. |

Replay includes exporter/subprocess work, gathering, encoding, complete response reading and
collector-success/sample-count checks;
it excludes FRR JSON-generation cost and remote network latency. Its CPU includes replay children;
RSS peak is cumulative process high-water memory, not heap allocation. Live container memory
includes FRR and file cache. Live FRR at 256 VTEPs per VNI remains unqualified.

## Limits

This candidate does not establish appliance readiness: selected-image/build/update/security
ownership, rootful RHEL 10/SELinux, FIPS, target platforms, socket sharing, lifecycle and remote
scraping need qualification. A static build using ordinary Go crypto is not a FIPS-validated build.
Check new FRR releases with `FRR_IMAGE=... make smoke`; JSON shapes vary.

All named FRR series in the EVPN Gateway Appliance (EGA) plan are implemented. Expected-inventory lifecycle, appliance
and interface signals, AWS state, dashboards and forwarding/latency probes belong to deployment
and other sources. Membership and route counts do not prove forwarding; BFD RTT remains
unexported pending a trustworthy latency source. EGA's current acceptance criteria require the
frr-k8s binary; using this candidate requires amended criteria. Delivery choice and per-VTEP
shipping policy remain open.

## License

Apache-2.0. Existing BGP metric compatibility follows the Apache-2.0 MetalLB/frr-k8s exporter.
